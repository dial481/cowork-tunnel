#!/usr/bin/env python3
"""Universal WebSocket-to-TCP jump relay.

Install on ONE server. Routes connections to ANY target host:port.
Acts as a bastion/jump host over WebSocket.

The target is specified via the 'target' query parameter:
  wss://jump.example.com/ssh?target=192.168.1.1:22&token=xxx

Security model:
  1. Bearer token authentication (rejects before the tunnel opens)
  2. sshd on the target still requires a valid SSH key

By default this relay will connect to ANY target, including hosts on the
relay's own private network. That is the point of a jump host. The bearer
token is the access control. Treat the token like an SSH private key.

Two optional restrictions are available if you want them:
  ALLOWED_HOSTS - only these targets are reachable
  BLOCK_PRIVATE - refuse targets that resolve to private/loopback addresses

Usage:
  # Generate a token
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"

  # Run (reaches any target)
  RELAY_TOKEN=<token> python3 universal.py

  # Restrict to specific targets
  RELAY_TOKEN=<token> ALLOWED_HOSTS="server1.com,192.168.1.5,10.0.0.0/8" python3 universal.py

  # Refuse private targets (public internet only)
  RELAY_TOKEN=<token> BLOCK_PRIVATE=1 python3 universal.py

Environment variables:
  RELAY_TOKEN      - Required. Bearer token for authentication.
  WS_HOST          - Listen address (default: 127.0.0.1)
  WS_PORT          - Listen port (default: 8765)
  MAX_CONNECTIONS  - Max concurrent tunnels (default: 10)
  RATE_LIMIT       - Max new connections per minute (default: 20). See README:
                     behind a reverse proxy this is a single shared bucket,
                     not per-client.
  ALLOWED_HOSTS    - Comma-separated hostnames, IPs, or CIDR ranges.
                     Empty (default) = any target allowed.
  BLOCK_PRIVATE    - Set to 1/true/yes to refuse private/loopback targets.
                     Default off. Entries in ALLOWED_HOSTS override this.
  DEFAULT_PORT     - Default port if not specified in target (default: 22)
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import logging
import os
import re
import signal
import socket
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
WS_HOST = os.environ.get("WS_HOST", "127.0.0.1")
WS_PORT = int(os.environ.get("WS_PORT", "8765"))
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "10"))
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "20"))
DEFAULT_PORT = int(os.environ.get("DEFAULT_PORT", "22"))

_TRUTHY = {"1", "true", "yes", "on"}
BLOCK_PRIVATE = os.environ.get("BLOCK_PRIVATE", "").strip().lower() in _TRUTHY

CONNECT_TIMEOUT = 10  # seconds to establish the TCP connection to the target
RESOLVE_TIMEOUT = 5  # seconds to resolve the target hostname
BUF_SIZE = 65536

# Allowlist: comma-separated hostnames, IPs, or CIDR ranges
ALLOWED_HOSTS: set[str] = set()
ALLOWED_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

for _entry in os.environ.get("ALLOWED_HOSTS", "").split(","):
    _entry = _entry.strip()
    if not _entry:
        continue
    try:
        ALLOWED_NETS.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError:
        ALLOWED_HOSTS.add(_entry.lower())

ALLOWLIST_ACTIVE = bool(ALLOWED_HOSTS or ALLOWED_NETS)

log = logging.getLogger("relay")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [jump] %(levelname)s %(message)s",
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
# Target parsing
# ---------------------------------------------------------------------------
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_target(raw: str) -> tuple[str, int] | None:
    """Parse a target into (host, port).

    Accepts 'host', 'host:port', '[v6addr]', '[v6addr]:port' and a bare IPv6
    address. Returns None if the target is malformed or the port is out of
    range.
    """
    raw = raw.strip()
    if not raw:
        return None

    port = DEFAULT_PORT

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return None
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                return None
            port = int(rest[1:])
        if not _is_ip(host):
            return None
    elif raw.count(":") > 1:
        # Bare IPv6 literal; a port would be ambiguous without brackets.
        if not _is_ip(raw):
            return None
        host = raw
    elif ":" in raw:
        host, _, port_s = raw.rpartition(":")
        if not port_s.isdigit():
            return None
        port = int(port_s)
    else:
        host = raw

    if not host:
        return None
    if not _is_ip(host) and not _HOSTNAME_RE.match(host):
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def _host_allowlisted(host: str) -> bool:
    """Check a literal target host against the allowlist."""
    if not ALLOWLIST_ACTIVE:
        return False
    if host.lower() in ALLOWED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_NETS)


def _ip_allowlisted(ip: str) -> bool:
    """Check a resolved IP against the allowlist's CIDR entries."""
    if not ALLOWED_NETS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_NETS)


def _is_private(ip: str) -> bool:
    """Report whether an address is private, loopback, reserved, or CGNAT."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_private or addr.is_reserved:
        return True
    if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    # RFC 6598 carrier-grade NAT is not covered by is_private.
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


async def _resolve(host: str, port: int) -> list[tuple[int, str]]:
    """Resolve a target to a list of (family, ip) without blocking the loop."""
    if _is_ip(host):
        family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
        return [(family, host)]
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
        timeout=RESOLVE_TIMEOUT,
    )
    seen: list[tuple[int, str]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if (family, ip) not in seen:
            seen.append((family, ip))
    return seen


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def _request_path(websocket) -> str:
    try:
        return websocket.request.path if hasattr(websocket, "request") else websocket.path
    except Exception:
        return getattr(websocket, "path", "/")


def _query(websocket) -> dict[str, list[str]]:
    path = _request_path(websocket)
    if "?" not in path:
        return {}
    return parse_qs(urlparse(path).query)


def _headers(websocket):
    try:
        return (
            websocket.request.headers
            if hasattr(websocket, "request")
            else websocket.request_headers
        )
    except Exception:
        return getattr(websocket, "request_headers", {})


def _extract_token(websocket) -> str | None:
    token = _query(websocket).get("token", [None])[0]
    if not token:
        headers = _headers(websocket)
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
            # Signal EOF to the target so it closes and unblocks tcp_to_ws.
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

    raw_target = _query(websocket).get("target", [None])[0]
    if not raw_target:
        await websocket.close(4001, "Missing target parameter")
        return

    parsed = _parse_target(raw_target)
    if not parsed:
        await websocket.close(4001, f"Invalid target: {raw_target[:64]}")
        return
    target_host, target_port = parsed

    allowlisted = _host_allowlisted(target_host)

    # Resolve once, up front. Every later decision uses the resolved address,
    # and we connect to that exact address -- never re-resolving the name.
    # That is what stops a DNS rebind between the check and the connect.
    try:
        candidates = await _resolve(target_host, target_port)
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        log.warning("Cannot resolve %s", target_host)
        await websocket.close(1011, "Cannot resolve target")
        return
    if not candidates:
        await websocket.close(1011, "Cannot resolve target")
        return

    # An explicit allowlist entry is a deliberate decision and overrides the
    # private-address guard -- otherwise allowlisting an internal host could
    # never work.
    if ALLOWLIST_ACTIVE and not allowlisted:
        if not any(_ip_allowlisted(ip) for _family, ip in candidates):
            log.warning("Target not in allowlist: %s", raw_target)
            await websocket.close(4002, "Target not allowed")
            return
        allowlisted = True

    if BLOCK_PRIVATE and not allowlisted:
        private = [ip for _family, ip in candidates if _is_private(ip)]
        if private:
            log.warning("Blocked private target: %s -> %s", raw_target, private[0])
            await websocket.close(4002, "Private addresses not allowed")
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

    # Connect to a validated IP literal, not the hostname.
    family, dest_ip = candidates[0]
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(dest_ip, target_port, family=family),
            timeout=CONNECT_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log.error("Connection timeout to %s:%d", dest_ip, target_port)
        await websocket.close(1011, "Target connection timeout")
        return
    except OSError as e:
        log.error("Cannot reach %s:%d: %s", dest_ip, target_port, e)
        await websocket.close(1011, "Target unreachable")
        return

    _active += 1
    log.info("%s -> %s:%d (active: %d)", remote_ip, dest_ip, target_port, _active)
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
        log.info("Closed %s:%d (active: %d)", dest_ip, target_port, _active)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    if not RELAY_TOKEN:
        log.error("Set RELAY_TOKEN environment variable before starting")
        sys.exit(1)

    mode = "RESTRICTED" if ALLOWLIST_ACTIVE else "OPEN (any target)"
    log.info(
        "Universal jump relay on %s:%d [%s] (max %d)", WS_HOST, WS_PORT, mode, MAX_CONNECTIONS
    )
    if ALLOWED_HOSTS:
        log.info("Allowed hosts: %s", ", ".join(sorted(ALLOWED_HOSTS)))
    if ALLOWED_NETS:
        log.info("Allowed networks: %s", ", ".join(str(n) for n in ALLOWED_NETS))
    if BLOCK_PRIVATE:
        log.info("Private/loopback targets are blocked (BLOCK_PRIVATE)")

    async with serve(bridge, WS_HOST, WS_PORT, ping_interval=30, ping_timeout=120, max_size=None):
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()

    log.info("Relay shut down")


if __name__ == "__main__":
    asyncio.run(main())
