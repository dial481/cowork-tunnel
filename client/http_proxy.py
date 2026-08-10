#!/usr/bin/env python3
"""HTTP proxy client for cowork-tunnel.

Forwards HTTP requests through a cowork-tunnel relay, bypassing HTTPS
restrictions in sandboxed environments (like Anthropic Cowork cloud).

Works as both a library and a CLI tool. Uses only stdlib (urllib.request).

Library usage:
    from http_proxy import relay_fetch

    response = relay_fetch(
        method="GET",
        url="https://api.github.com/repos/owner/repo",
        headers={"Authorization": "token ghp_xxx"},
    )
    # response = {"status": 200, "headers": {...}, "body": b"...", "body_b64": "..."}

CLI usage:
    export COWORK_RELAY_URL="https://cowork-tunnel.example.workers.dev"
    export COWORK_RELAY_TOKEN="your-token"

    python3 http_proxy.py GET https://api.github.com/repos/owner/repo
    python3 http_proxy.py POST https://example.com/api -H "Content-Type: application/json" -d '{"key":"value"}'
    python3 http_proxy.py GET https://example.com/binary --raw > output.bin
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def _env_float(name: str, default: float) -> float:
    """Read a positive float from the environment, falling back on garbage."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# ---------------------------------------------------------------------------
# Hop-by-hop headers to strip before forwarding
# ---------------------------------------------------------------------------
HOP_BY_HOP = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})


# The relay answers a single JSON round-trip, but the target it forwards to may
# be slow. This bounds the client so a stalled relay cannot hang a script
# forever -- urllib's default is to block indefinitely.
DEFAULT_TIMEOUT = 60

# Identify ourselves to the relay. This is not cosmetic: Cloudflare's edge
# blocks urllib's default "Python-urllib/x.y" agent outright, so a Worker-hosted
# relay answers 403 (error 1010) before the request ever reaches the Worker.
# Overridable for the same reason -- if an edge ever blocks this string too,
# it can be changed without editing the file.
RELAY_USER_AGENT = os.environ.get("COWORK_RELAY_USER_AGENT", "").strip() or "cowork-tunnel"


def _make_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for talking to the relay.

    Cowork cloud sessions run behind a TLS-intercepting proxy that re-signs
    all certificates, so verification against the system trust store always
    fails and is off by default. Set COWORK_RELAY_VERIFY_TLS=1 when running
    somewhere with a clean network path to the relay.
    """
    if os.environ.get("COWORK_RELAY_VERIFY_TLS", "").strip().lower() in ("1", "true", "yes", "on"):
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_opener(ssl_ctx: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """Build an opener that ignores the sandbox's HTTPS_PROXY settings.

    The Cowork sandbox points HTTPS_PROXY at a local egress proxy; we want a
    direct connection to the relay. An empty ProxyHandler disables proxying for
    these requests only, rather than deleting the variables from os.environ and
    changing behaviour for every other library in the process.
    """
    handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({})]
    if ssl_ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    return urllib.request.build_opener(*handlers)


def _normalize_relay_url(raw: str) -> str:
    """Convert a relay URL to the HTTP proxy endpoint.

    If COWORK_RELAY_URL is ``wss://host/path?query``, extract just
    ``https://host`` and append ``/proxy``.  If it already starts with
    ``http://`` or ``https://``, strip any path/query and append ``/proxy``.
    """
    # wss:// -> https://, ws:// -> http://
    if raw.startswith("wss://"):
        raw = "https://" + raw[6:]
    elif raw.startswith("ws://"):
        raw = "http://" + raw[5:]

    # Strip path and query -- keep only scheme + authority
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path.split("/")[0]
    return f"{scheme}://{netloc}/proxy"


def _strip_hop_by_hop(headers: dict[str, str]) -> dict[str, str]:
    """Remove hop-by-hop headers from a header dict."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


def relay_fetch(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    *,
    relay_url: str | None = None,
    relay_token: str | None = None,
    timeout: float | None = None,
) -> dict:
    """Send an HTTP request through the cowork-tunnel relay.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Target URL (full, including scheme)
        headers: Headers to send to the target
        body: Request body (str or bytes)
        relay_url: Override for COWORK_RELAY_URL
        relay_token: Override for COWORK_RELAY_TOKEN
        timeout: Seconds to wait for the relay (default: COWORK_RELAY_TIMEOUT
            or 60). Never None in effect -- an unbounded wait would hang the
            caller if the relay stalls.

    Returns:
        Dict with keys: status, headers, body (bytes), body_b64 (str). A
        ``set_cookie`` list is present when the target sent Set-Cookie headers,
        which cannot be folded into the flat header dict without corrupting
        them.

    Raises:
        ValueError: if no relay URL is configured.
        RuntimeError: if the relay is unreachable or returns an error.
    """
    if relay_url is None:
        relay_url = os.environ.get("COWORK_RELAY_URL", "")
    if relay_token is None:
        relay_token = os.environ.get("COWORK_RELAY_TOKEN", "")

    if not relay_url:
        raise ValueError("No relay URL: set COWORK_RELAY_URL or pass relay_url")

    proxy_endpoint = _normalize_relay_url(relay_url)

    # Build the JSON envelope
    envelope: dict = {
        "url": url,
        "method": method.upper(),
    }

    out_headers = _strip_hop_by_hop(headers) if headers else {}
    # Many APIs refuse a request with no User-Agent -- GitHub answers 403. This
    # client is the user agent making that request, so it names itself unless
    # the caller already did. Anything the caller supplies wins, including a
    # differently-cased "user-agent".
    if not any(k.lower() == "user-agent" for k in out_headers):
        out_headers["User-Agent"] = RELAY_USER_AGENT
    envelope["headers"] = out_headers

    if body is not None:
        if isinstance(body, bytes):
            envelope["body_b64"] = base64.b64encode(body).decode("ascii")
        else:
            envelope["body"] = body

    payload = json.dumps(envelope).encode("utf-8")

    # Build the request to the relay
    req = urllib.request.Request(
        proxy_endpoint,
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    # The agent for the hop to the relay. Headers meant for the target travel
    # inside the envelope and are untouched by this.
    req.add_header("User-Agent", RELAY_USER_AGENT)
    if relay_token:
        req.add_header("Authorization", f"Bearer {relay_token}")

    if timeout is None:
        timeout = _env_float("COWORK_RELAY_TIMEOUT", DEFAULT_TIMEOUT)

    ssl_ctx = _make_ssl_context() if proxy_endpoint.startswith("https://") else None
    opener = _build_opener(ssl_ctx)

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        # Read the error body for diagnostics
        err_body = b""
        try:
            err_body = e.read()
        except Exception:
            pass
        try:
            err_data = json.loads(err_body)
            error_msg = err_data.get("error", f"HTTP {e.code}")
        except (json.JSONDecodeError, ValueError):
            error_msg = err_body.decode("utf-8", errors="replace") if err_body else f"HTTP {e.code}"
        raise RuntimeError(f"Relay error ({e.code}): {error_msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach relay at {proxy_endpoint}: {e.reason}") from e
    except TimeoutError as e:
        raise RuntimeError(f"Relay at {proxy_endpoint} timed out after {timeout}s") from e

    try:
        result = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise RuntimeError(f"Relay returned a non-JSON response: {raw[:200]!r}") from e
    if not isinstance(result, dict) or "status" not in result:
        raise RuntimeError(f"Relay returned a malformed envelope: {str(result)[:200]}")

    # Decode the response body
    if result.get("body_b64"):
        try:
            result["body"] = base64.b64decode(result["body_b64"])
        except (binascii.Error, ValueError) as e:
            raise RuntimeError("Relay returned an undecodable body") from e
    else:
        result["body"] = b""

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        # No prog=: argparse derives it from argv[0], so this reads
        # "cowork-tunnel-http" when installed and "http_proxy.py" when the file
        # is run directly. Both are true; a hardcoded name is only ever right
        # for one of them.
        description="Forward HTTP requests through a cowork-tunnel relay.",
    )
    parser.add_argument("method", metavar="METHOD", help="HTTP method (GET, POST, ...)")
    parser.add_argument("url", metavar="URL", help="Target URL")
    parser.add_argument(
        "-H", "--header", dest="headers", action="append", default=[],
        metavar="HEADER",
        help="Add a header (e.g. -H 'Content-Type: application/json'). Repeatable.",
    )
    parser.add_argument("-d", "--data", dest="body", default=None, help="Request body string")
    parser.add_argument(
        "-b", "--body-file", dest="body_file", default=None,
        help="Read request body from file (binary safe, sent as body_b64)",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Print only the response body to stdout (for piping)",
    )
    return parser


def _parse_headers(header_args: list[str]) -> dict[str, str]:
    """Parse -H arguments into a dict."""
    headers: dict[str, str] = {}
    for h in header_args:
        if ":" not in h:
            print(f"Warning: ignoring malformed header: {h!r}", file=sys.stderr)
            continue
        key, _, value = h.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    headers = _parse_headers(args.headers)

    body: bytes | str | None = None
    if args.body_file:
        with open(args.body_file, "rb") as f:
            body = f.read()
    elif args.body is not None:
        body = args.body

    try:
        result = relay_fetch(
            method=args.method,
            url=args.url,
            headers=headers or None,
            body=body,
        )
    except (RuntimeError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.raw:
        print(f"HTTP {result['status']}", file=sys.stderr)
        for k, v in (result.get("headers") or {}).items():
            print(f"{k}: {v}", file=sys.stderr)
        for cookie in result.get("set_cookie") or []:
            print(f"Set-Cookie: {cookie}", file=sys.stderr)
        if result.get("redirected"):
            print(f"(redirected to {result.get('final_url', '?')})", file=sys.stderr)

    # Write the body as bytes so binary responses survive the pipe intact.
    body_bytes = result.get("body") or b""
    if not isinstance(body_bytes, bytes):
        body_bytes = str(body_bytes).encode("utf-8")
    sys.stdout.buffer.write(body_bytes)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
