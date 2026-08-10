#!/usr/bin/env python3
"""Universal WebSocket-to-TCP jump relay with HTTP forwarding.

Install on ONE server. Two modes, two local ports:
  1. WS_PORT    - WebSocket upgrade -> SSH tunneling to any target host:port
  2. PROXY_PORT - POST /proxy       -> HTTP request forwarding to any http(s) URL

Clients never see either port. A reverse proxy terminates TLS on 443 and routes
by path -- /ssh to WS_PORT, /proxy and /health to PROXY_PORT -- so the single
entry point that restricted clients depend on is preserved. See
relay/nginx-location.conf.

The target is specified via the 'target' query parameter:
  wss://jump.example.com/ssh?target=192.168.1.1:22&token=xxx

HTTP proxy requests use a JSON envelope:
  POST /proxy with {"url": "...", "method": "GET", "headers": {...}}

Security model:
  1. Bearer token authentication (rejects before the tunnel opens)
  2. sshd on the target still requires a valid SSH key

By default this relay will connect to ANY target, including hosts on the
relay's own private network. That is the point of a jump host. The bearer
token is the access control. Treat the token like an SSH private key.

Two optional restrictions are available if you want them:
  ALLOWED_HOSTS - only these targets are reachable
  BLOCK_PRIVATE - refuse targets that resolve to private/loopback addresses

Both apply to the SSH path only. The HTTP proxy path forwards to any http(s)
URL by design; the caller supplies their own upstream credentials and the relay
stores nothing. Non-HTTP schemes (file:, ftp:, data:) are refused outright --
they would turn the proxy into an arbitrary local file reader.

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
  RELAY_TOKEN       - Required. Bearer token for authentication.
  WS_HOST           - Listen address for both ports (default: 127.0.0.1)
  WS_PORT           - SSH/WebSocket listen port (default: 8765)
  PROXY_PORT        - HTTP proxy listen port, serving /proxy and /health
                      (default: 8766). Must differ from WS_PORT.
  MAX_CONNECTIONS   - Max concurrent SSH tunnels (default: 10)
  RATE_LIMIT        - Max new tunnels per minute (default: 20). See README:
                      behind a reverse proxy this is a single shared bucket,
                      not per-client.
  PROXY_RATE_LIMIT  - Max HTTP proxy requests per minute (default: 120).
  MAX_PROXY_BODY    - Max HTTP proxy request body in bytes (default: 8 MiB).
  MAX_RESPONSE_BODY - Max upstream response body in bytes (default: 32 MiB).
                      The body is buffered and base64-encoded in memory, so
                      this bounds relay memory at roughly 2.5x the value.
  PROXY_TIMEOUT     - Upstream request timeout in seconds (default: 25).
  HEAD_TIMEOUT      - Seconds a client may take to send a complete request
                      head before the connection is dropped (default: 15).
  BODY_TIMEOUT      - Seconds a client may take to send the declared request
                      body (default: 30).
  INSECURE_UPSTREAM_TLS - Set to 1/true/yes to skip certificate verification on
                      upstream HTTPS requests. Off by default. Only enable if
                      the relay itself sits behind a TLS-intercepting gateway.
  ALLOWED_HOSTS     - Comma-separated hostnames, IPs, or CIDR ranges.
                      Empty (default) = any target allowed. SSH path only.
  BLOCK_PRIVATE     - Set to 1/true/yes to refuse private/loopback targets.
                      Default off. Entries in ALLOWED_HOSTS override this.
                      SSH path only.
  DEFAULT_PORT      - Default port if not specified in target (default: 22)

Why two listeners instead of one
-------------------------------
SSH and the HTTP proxy could share a port, but not cheaply. Two routes into
websockets are closed:

  * Its process_request hook cannot serve /proxy. The hook never sees a request
    body -- the library parses only the request line and headers -- and its
    signature differs between the legacy and asyncio implementations.
  * It cannot be handed an already-accepted socket. serve() takes a listening
    socket; there is no public entry point for a live connection.

That leaves two single-port designs. Building a ServerConnection by hand and
swapping it onto the transport rests on four pieces of websockets' internals;
an earlier version of this file did exactly that and broke the SSH bridge on
13.1, 14.2, 15.0 and 16.0 while passing on 17.x. Dispatching in front of a
loopback websockets server avoids the internals but puts a hand-written HTTP
parser in front of every tunnel.

Separate ports cost neither. websockets owns WS_PORT outright, exactly as it
did before the proxy existed, so nothing sits between a client and the
library's own handshake. The HTTP handlers own PROXY_PORT and never see tunnel
traffic. Clients are unaffected: they reach one TLS endpoint and the reverse
proxy routes by path. Both listeners are plaintext and expect to sit behind
that proxy -- which every real deployment already requires, since neither the
client's wss:// nor an HTTPS-only egress path can talk to a plaintext relay.

Throughput did not drive this choice. All three designs measure the same
(~175-240 MiB/s over loopback); the only change that moved the number was
disabling permessage-deflate, which is worth roughly 17x on its own. See the
comment on serve() in main().
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import parse_qs, urlparse, urlsplit

try:
    import websockets
    from websockets.asyncio.server import serve
except ImportError:
    print("[relay] pip install 'websockets>=14.1'", file=sys.stderr)
    sys.exit(1)


def _env_int(name: str, default: int) -> int:
    """Read a positive integer from the environment, falling back on garbage."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


_TRUTHY = {"1", "true", "yes", "on"}


def _env_flag(name: str) -> bool:
    """Read a boolean flag from the environment."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "")
WS_HOST = os.environ.get("WS_HOST", "127.0.0.1")
WS_PORT = _env_int("WS_PORT", 8765)
PROXY_PORT = _env_int("PROXY_PORT", 8766)
MAX_CONNECTIONS = _env_int("MAX_CONNECTIONS", 10)
RATE_LIMIT = _env_int("RATE_LIMIT", 20)
PROXY_RATE_LIMIT = _env_int("PROXY_RATE_LIMIT", 120)
DEFAULT_PORT = _env_int("DEFAULT_PORT", 22)
MAX_PROXY_BODY = _env_int("MAX_PROXY_BODY", 8 * 1024 * 1024)
MAX_RESPONSE_BODY = _env_int("MAX_RESPONSE_BODY", 32 * 1024 * 1024)
PROXY_TIMEOUT = _env_int("PROXY_TIMEOUT", 25)
INSECURE_UPSTREAM_TLS = _env_flag("INSECURE_UPSTREAM_TLS")
BLOCK_PRIVATE = _env_flag("BLOCK_PRIVATE")

CONNECT_TIMEOUT = 10  # seconds to establish the TCP connection to the target
RESOLVE_TIMEOUT = 5  # seconds to resolve the target hostname
BUF_SIZE = 65536

# A client that opens a connection and then stalls holds a file descriptor for
# as long as we let it. Every phase of reading a request is bounded.
HEAD_TIMEOUT = _env_int("HEAD_TIMEOUT", 15)  # seconds to send a complete head
BODY_TIMEOUT = _env_int("BODY_TIMEOUT", 30)  # seconds to send the declared body
# Request line + headers. Doubles as the HTTP server's stream limit, which is
# safe here because no tunnel traffic crosses that server -- readuntil() raises
# past this bound and the request is refused with 431.
MAX_HEAD_BYTES = 32 * 1024

# Schemes the HTTP proxy will forward. urllib can also open file:, ftp: and
# data: URLs; allowing those would let any token holder read the relay's disk.
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Hop-by-hop headers that must not be forwarded through the HTTP proxy.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})

# RFC 9110 token, used for method names and header field names.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# A header value may not carry control characters; CR/LF would inject headers.
_HEADER_VALUE_RE = re.compile(r"^[\t\x20-\x7e\x80-\xff]*$")

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
# is intentional for a single-user relay; see README. Tunnels and HTTP proxy
# requests get separate buckets because their natural rates differ by an order
# of magnitude.
# ---------------------------------------------------------------------------
_conn_times: dict[str, list[float]] = defaultdict(list)
_proxy_times: dict[str, list[float]] = defaultdict(list)
_active: int = 0


def _rate_ok(ip: str, *, table: dict[str, list[float]] | None = None,
             limit: int | None = None) -> bool:
    """Record a request from `ip` and report whether it is within the limit."""
    if table is None:
        table = _conn_times
    if limit is None:
        limit = RATE_LIMIT
    now = time.monotonic()
    recent = [t for t in table[ip] if now - t < 60]
    # Drop keys that have gone quiet so the table cannot grow without bound.
    for key in [k for k, v in table.items() if k != ip and (not v or now - v[-1] >= 60)]:
        del table[key]
    if len(recent) >= limit:
        table[ip] = recent
        return False
    recent.append(now)
    table[ip] = recent
    return True


def _proxy_rate_ok(ip: str) -> bool:
    """Record an HTTP proxy request and report whether it is within the limit."""
    return _rate_ok(ip, table=_proxy_times, limit=PROXY_RATE_LIMIT)


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
def _client_ip(websocket) -> str:
    """Return the address the WebSocket client connected from."""
    addr = getattr(websocket, "remote_address", None)
    return addr[0] if addr else "0.0.0.0"


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
        log.warning("Auth failed from %s", _client_ip(websocket))
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

    remote_ip = _client_ip(websocket)
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
# HTTP responses
# ---------------------------------------------------------------------------
_REASONS = {
    100: "Continue", 200: "OK", 400: "Bad Request", 401: "Unauthorized",
    405: "Method Not Allowed", 408: "Request Timeout", 411: "Length Required",
    413: "Payload Too Large", 426: "Upgrade Required",
    429: "Too Many Requests", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def _http_response(status: int, body: bytes, content_type: str = "application/json") -> bytes:
    """Build a minimal HTTP/1.1 response."""
    lines = [
        f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Cache-Control: no-store",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii") + body


def _json_response(status: int, data: dict) -> bytes:
    """Build an HTTP response with a JSON body."""
    return _http_response(status, json.dumps(data).encode("utf-8"))


def _json_error(status: int, message: str) -> bytes:
    """Build an HTTP error response."""
    return _json_response(status, {"error": message})


# ---------------------------------------------------------------------------
# HTTP proxy
# ---------------------------------------------------------------------------
class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never off http(s).

    Refusing by raising HTTPError means the caller receives the redirect
    response itself -- status and Location header, no body fetched from the
    refused scheme. That is more useful than an opaque error and never reads
    anything off the relay's disk.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if urlsplit(newurl).scheme.lower() not in ALLOWED_SCHEMES:
            raise urllib.error.HTTPError(newurl, code, "Redirect to non-HTTP scheme refused",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener() -> urllib.request.OpenerDirector:
    """Build an opener that can ONLY speak http(s).

    urllib's default opener also handles file:, ftp: and data: URLs. Rather
    than blocklisting those, this opener is assembled from exactly the handlers
    the proxy needs, so an unsupported scheme has no handler to reach.
    """
    if INSECURE_UPSTREAM_TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()

    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
        _StrictRedirectHandler(),
        # Turns a non-2xx response into an HTTPError so the caller can forward
        # the target's own status instead of silently getting None back.
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)

    # urllib stamps "User-Agent: Python-urllib/x.y" onto any request that does
    # not carry one. A forwarding proxy must not invent request headers: it
    # made the caller's request look like something it was not, it diverged
    # from the Cloudflare Worker (which adds nothing), and "Python-urllib" is
    # itself blocked by Cloudflare-fronted targets. The envelope decides.
    opener.addheaders = []
    return opener


_OPENER = _build_opener()


def _flatten_response_headers(message) -> tuple[dict[str, str], list[str]]:
    """Flatten response headers to a dict, keeping Set-Cookie separate.

    Duplicate headers are joined with ', ' to match the Fetch API's behaviour
    in the Cloudflare Worker. Set-Cookie is exempt: joining cookies corrupts
    them, so they are returned as a list for the caller to use verbatim.
    """
    flat: dict[str, str] = {}
    cookies: list[str] = []
    for key, value in message.items():
        lower = key.lower()
        if lower in _HOP_BY_HOP:
            continue
        if lower == "set-cookie":
            cookies.append(value)
            continue
        flat[key] = f"{flat[key]}, {value}" if key in flat else value
    return flat, cookies


class _EnvelopeError(ValueError):
    """The proxy envelope is malformed; carries the client-facing message."""


def _prepare_request(envelope: dict) -> urllib.request.Request:
    """Validate an envelope and turn it into a urllib Request.

    Raises:
        _EnvelopeError: if any field is missing, malformed, or unsafe.
    """
    target_url = envelope.get("url")
    if not target_url or not isinstance(target_url, str):
        raise _EnvelopeError("missing or invalid 'url'")

    method = envelope.get("method")
    if not method or not isinstance(method, str):
        raise _EnvelopeError("missing or invalid 'method'")
    method = method.upper()
    if not _TOKEN_RE.match(method):
        raise _EnvelopeError("invalid 'method'")

    split = urlsplit(target_url)
    if split.scheme.lower() not in ALLOWED_SCHEMES:
        raise _EnvelopeError(f"unsupported URL scheme: {split.scheme[:16] or '(none)'}")
    if not split.netloc:
        raise _EnvelopeError("invalid 'url': no host")

    raw_headers = envelope.get("headers") or {}
    if not isinstance(raw_headers, dict):
        raise _EnvelopeError("invalid 'headers'")
    out_headers = {}
    for key, value in raw_headers.items():
        if not isinstance(key, str) or not _TOKEN_RE.match(key):
            raise _EnvelopeError(f"invalid header name: {str(key)[:32]}")
        if key.lower() in _HOP_BY_HOP:
            continue
        text = value if isinstance(value, str) else str(value)
        # A CR or LF here would let the caller inject extra request headers.
        if not _HEADER_VALUE_RE.match(text):
            raise _EnvelopeError(f"invalid value for header: {key[:32]}")
        out_headers[key] = text

    body: bytes | None = None
    if envelope.get("body_b64"):
        raw_b64 = envelope["body_b64"]
        if not isinstance(raw_b64, str):
            raise _EnvelopeError("invalid 'body_b64'")
        try:
            body = base64.b64decode(raw_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _EnvelopeError("invalid 'body_b64': not valid base64") from exc
    elif envelope.get("body") is not None:
        raw_body = envelope["body"]
        if isinstance(raw_body, str):
            body = raw_body.encode("utf-8")
        elif isinstance(raw_body, bytes):
            body = raw_body
        else:
            raise _EnvelopeError("invalid 'body': expected a string")

    # A body on GET/HEAD is meaningless and some servers reject it outright.
    if method in ("GET", "HEAD"):
        body = None

    request = urllib.request.Request(target_url, data=body, method=method)
    for key, value in out_headers.items():
        request.add_header(key, value)
    return request


def _fetch_upstream(request: urllib.request.Request) -> dict:
    """Perform the upstream request. Blocking; call via asyncio.to_thread."""
    requested_url = request.full_url

    def describe(resp, status: int) -> dict:
        body = resp.read(MAX_RESPONSE_BODY + 1)
        if len(body) > MAX_RESPONSE_BODY:
            return {"error": f"Upstream response exceeds {MAX_RESPONSE_BODY} bytes"}
        headers, cookies = _flatten_response_headers(resp.headers)
        result = {
            "status": status,
            "headers": headers,
            "body_b64": base64.b64encode(body).decode("ascii"),
        }
        if cookies:
            result["set_cookie"] = cookies
        final_url = getattr(resp, "url", requested_url)
        if final_url and final_url != requested_url:
            result["redirected"] = True
            result["final_url"] = final_url
        return result

    try:
        with _OPENER.open(request, timeout=PROXY_TIMEOUT) as resp:
            return describe(resp, resp.status)
    except urllib.error.HTTPError as e:
        # An HTTP error response is a real answer from the target; pass it on.
        try:
            return describe(e, e.code)
        except Exception as exc:  # noqa: BLE001 - a truncated error body is not fatal
            return {"status": e.code, "headers": {}, "body_b64": "",
                    "error": f"Upstream error body unreadable: {exc}"}
        finally:
            try:
                e.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
    except urllib.error.URLError as e:
        return {"error": f"Upstream error: {e.reason}"}
    except TimeoutError:
        # A stall after the response head arrives surfaces here, not as URLError.
        return {"error": "Upstream error: timed out"}
    except Exception as e:  # noqa: BLE001 - never let one request kill the relay
        return {"error": f"Upstream error: {e}"}


async def _handle_proxy(headers: dict[str, str], body: bytes, peer: str) -> bytes:
    """Handle a POST /proxy request and return the raw HTTP response."""
    if not RELAY_TOKEN:
        return _json_error(500, "Server misconfigured")

    auth = headers.get("authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if not token or not _token_valid(token):
        log.warning("Proxy auth failed from %s", peer)
        return _json_error(401, "Forbidden")

    if not _proxy_rate_ok(peer):
        log.warning("Proxy rate limit hit for %s", peer)
        return _json_error(429, "Too many requests")

    try:
        envelope = json.loads(body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return _json_error(400, "Bad request: invalid JSON")
    if not isinstance(envelope, dict):
        return _json_error(400, "Bad request: envelope must be a JSON object")

    try:
        request = _prepare_request(envelope)
    except _EnvelopeError as e:
        return _json_error(400, f"Bad request: {e}")

    result = await asyncio.to_thread(_fetch_upstream, request)

    if "status" not in result:
        log.info("proxy %s %s -> %s", request.get_method(),
                 urlsplit(request.full_url).netloc, result.get("error"))
        return _json_error(502, result.get("error", "Upstream error"))

    log.info("proxy %s %s -> %s", request.get_method(),
             urlsplit(request.full_url).netloc, result["status"])
    return _json_response(200, result)


def _health_response() -> bytes:
    """Build the GET /health response."""
    return _json_response(200, {
        "status": "ok",
        "mode": "universal-relay",
        "capabilities": ["ssh", "proxy"],
    })


# ---------------------------------------------------------------------------
# HTTP server (proxy port)
# ---------------------------------------------------------------------------
class _BadRequest(Exception):
    """A request could not be parsed; carries the status and message to send."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    """Read the request line and headers, bounded in both size and time.

    The stream's limit is MAX_HEAD_BYTES, so readuntil() raises rather than
    buffering an unbounded head.
    """
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=HEAD_TIMEOUT)
    except asyncio.IncompleteReadError:
        return b""  # peer hung up before sending a complete head
    except asyncio.LimitOverrunError as e:
        raise _BadRequest(431, "Request header fields too large") from e
    except asyncio.TimeoutError as e:
        raise _BadRequest(408, "Request timeout") from e
    return head


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    """Split a request head into (method, path, headers)."""
    try:
        text = head.decode("iso-8859-1")
    except ValueError as e:  # pragma: no cover - iso-8859-1 decodes any byte
        raise _BadRequest(400, "Bad request: undecodable header") from e

    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise _BadRequest(400, "Bad request: malformed request line")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise _BadRequest(400, "Bad request: malformed header line")
        key, _, value = line.partition(":")
        key = key.strip().lower()
        # Duplicates are joined, matching how HTTP folds repeated fields.
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value

    return parts[0].upper(), parts[1], headers


async def _read_body(reader: asyncio.StreamReader, length: int) -> bytes:
    """Read exactly `length` bytes of request body, bounded in time."""
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=BODY_TIMEOUT)
    except asyncio.IncompleteReadError as e:
        raise _BadRequest(400, "Bad request: truncated body") from e
    except asyncio.TimeoutError as e:
        raise _BadRequest(408, "Request timeout") from e


def _content_length(headers: dict[str, str]) -> int:
    """Extract and validate Content-Length."""
    if "transfer-encoding" in headers:
        # Chunked bodies would need a de-chunker; nginx and every client we
        # ship send a measured body, so this is refused rather than guessed at.
        raise _BadRequest(411, "Bad request: chunked encoding not supported")
    raw = headers.get("content-length", "0").strip()
    if not raw.isdigit():
        raise _BadRequest(400, "Bad request: invalid Content-Length")
    return int(raw)


async def _serve_proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       headers: dict[str, str], peer: str) -> bytes:
    """Read the body for POST /proxy and produce the response."""
    length = _content_length(headers)

    if length > MAX_PROXY_BODY:
        # Drain a bounded amount so a marginally-oversized upload still gets a
        # readable 413 instead of a connection reset mid-send.
        try:
            await asyncio.wait_for(reader.read(MAX_PROXY_BODY + 1), timeout=BODY_TIMEOUT)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        return _json_error(413, "Request body too large")

    if headers.get("expect", "").lower() == "100-continue":
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()

    body = await _read_body(reader, length)
    return await _handle_proxy(headers, body, peer)


async def _serve_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Serve one HTTP request on the proxy port.

    Handles /proxy and /health only; no tunnel traffic reaches this server. The
    connection is closed exactly once on every path, and no exception escapes
    into the event loop.
    """
    peername = writer.get_extra_info("peername")
    peer = peername[0] if peername else "0.0.0.0"
    response: bytes | None = None
    # Bound before the try: the finally block consults it, and a request that
    # fails to parse never reaches the assignment below.
    method = ""

    try:
        head = await _read_head(reader)
        if not head:
            return

        method, target, headers = _parse_head(head)
        path = target.split("?", 1)[0]

        if path == "/proxy":
            if method != "POST":
                response = _json_error(405, "Method not allowed")
            else:
                response = await _serve_proxy(reader, writer, headers, peer)
        elif path == "/health":
            response = (
                _health_response() if method in ("GET", "HEAD")
                else _json_error(405, "Method not allowed")
            )
        else:
            response = _json_error(404, "Not found")

    except _BadRequest as e:
        response = _json_error(e.status, e.message)
    except (ConnectionError, asyncio.CancelledError):
        raise
    except Exception as e:  # noqa: BLE001 - one bad request must not kill the relay
        log.exception("Unhandled error serving %s: %s", peer, e)
        response = _json_error(500, "Internal server error")
    finally:
        try:
            if response is not None:
                # A HEAD response carries the same headers as the GET would,
                # including Content-Length, but no body. nginx strips it for us
                # in the documented deployment; a direct connection gets it
                # right only if we do it here.
                if method == "HEAD":
                    head_end = response.find(b"\r\n\r\n")
                    if head_end != -1:
                        response = response[: head_end + 4]
                writer.write(response)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    if not RELAY_TOKEN:
        log.error("Set RELAY_TOKEN environment variable before starting")
        sys.exit(1)

    if PROXY_PORT == WS_PORT:
        log.error("PROXY_PORT (%d) must differ from WS_PORT", PROXY_PORT)
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
    if INSECURE_UPSTREAM_TLS:
        log.warning("INSECURE_UPSTREAM_TLS is on: upstream certificates are NOT verified")

    # websockets owns the SSH port outright -- no wrapper, no interposed
    # protocol, nothing between the client and the library's own handshake.
    # compression=None is not a micro-optimisation. serve() negotiates
    # permessage-deflate by default, and this carries SSH -- an encrypted
    # stream, so incompressible by construction. Deflating it burns CPU on
    # every frame to produce slightly larger output. Measured on 100 MiB of
    # random data: 12.5 MiB/s with compression, 220 MiB/s without.
    try:
        ws_server = await serve(
            bridge, WS_HOST, WS_PORT,
            ping_interval=30, ping_timeout=120, max_size=None, compression=None,
        )
    except OSError as e:
        log.error("Cannot bind SSH port %s:%d: %s", WS_HOST, WS_PORT, e)
        sys.exit(1)

    try:
        http_server = await asyncio.start_server(
            _serve_http, WS_HOST, PROXY_PORT, limit=MAX_HEAD_BYTES,
        )
    except OSError as e:
        log.error("Cannot bind HTTP proxy port %s:%d: %s", WS_HOST, PROXY_PORT, e)
        ws_server.close()
        await ws_server.wait_closed()
        sys.exit(1)

    log.info("HTTP proxy on %s:%d (/proxy, /health)", WS_HOST, PROXY_PORT)

    try:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
    finally:
        http_server.close()
        await http_server.wait_closed()
        ws_server.close()
        await ws_server.wait_closed()

    log.info("Relay shut down")


if __name__ == "__main__":
    asyncio.run(main())
