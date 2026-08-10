#!/usr/bin/env python3
"""SSH ProxyCommand over WebSocket.

Tunnels SSH traffic through a WebSocket connection, allowing SSH from
environments that only permit HTTPS egress (e.g. Anthropic Cowork cloud).

Works with all three server options:
  - Standalone relay (per-server, connects to local sshd)
  - Universal relay  (one server, routes to any target)
  - Cloudflare Worker (serverless, routes to any target)

Usage as ProxyCommand:
  ssh -o 'ProxyCommand=python3 ws_proxy.py' user@host

Configuration via environment variables:
  COWORK_RELAY_URL   - WebSocket URL of the relay
  COWORK_RELAY_TOKEN - Bearer token for authentication

Or pass as arguments:
  python3 ws_proxy.py <url> <token>

For universal relay or Cloudflare Worker, append the target to the URL:
  COWORK_RELAY_URL="wss://relay.example.com/ssh?target=192.168.1.1:22"

Note: stdout is the SSH data channel. Nothing but tunnel bytes may ever be
written to it -- diagnostics go to stderr.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import sys

try:
    import websockets
except ImportError:
    import subprocess

    print("[ws_proxy] installing websockets...", file=sys.stderr)
    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "websockets",
                "-q",
                "--break-system-packages",
            ],
            # stdout is the SSH stream. pip must never write to it.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        print(
            "[ws_proxy] could not install websockets. Install it manually:\n"
            "  pip install websockets --break-system-packages",
            file=sys.stderr,
        )
        sys.exit(1)
    import websockets

try:
    from websockets.asyncio.client import connect
except ImportError:
    from websockets.client import connect  # type: ignore[assignment]

BUF_SIZE = 65536


def _make_ssl_context():
    """Create an SSL context that works through MITM egress gateways.

    Cowork cloud sessions run behind a TLS-intercepting proxy that re-signs
    all certificates, so standard verification always fails. SSH host key
    verification and key auth remain the real security layer end to end.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _clear_proxy_env():
    """Remove HTTPS proxy env vars so websockets connects directly.

    The Cowork sandbox sets HTTPS_PROXY pointing to a local egress proxy. The
    websockets library doesn't support CONNECT proxies natively, and the proxy
    interferes with WebSocket upgrades to non-allowlisted hosts. Direct
    connections work because the sandbox intercepts transparently anyway.
    """
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        os.environ.pop(key, None)


def _prog() -> str:
    """How this was invoked, for messages that tell the user what to run.

    Installed as a console script it is "cowork-tunnel-ssh"; run as a file it is
    "python3 ws_proxy.py". Hardcoding either one makes the advice wrong in the
    other case, and this is a ProxyCommand -- the message is the only thing the
    user sees when it is misconfigured.
    """
    name = os.path.basename(sys.argv[0] or "ws_proxy.py")
    return name if name.startswith("cowork-tunnel") else f"python3 {name}"


def _get_config() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]
    url = os.environ.get("COWORK_RELAY_URL", "")
    token = os.environ.get("COWORK_RELAY_TOKEN", "")
    if not url:
        print(
            f"Usage: {_prog()} <url> <token>\n"
            "   or: set COWORK_RELAY_URL and COWORK_RELAY_TOKEN env vars.\n\n"
            "URL examples:\n"
            "  Standalone:  wss://server.com/ssh\n"
            "  Universal:   wss://jump.example.com/ssh?target=host:22\n"
            "  Cloudflare:  wss://tunnel.you.workers.dev/?target=host:22",
            file=sys.stderr,
        )
        sys.exit(1)
    return url, token


async def _run_tunnel(ws) -> None:
    """Pipe stdin to the socket and the socket to stdout until either ends."""
    loop = asyncio.get_running_loop()

    reader = asyncio.StreamReader()
    try:
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
        )
        w_transport, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)
    except (ValueError, OSError) as e:
        raise RuntimeError(
            "stdin/stdout are not pipes. ws_proxy.py is an SSH ProxyCommand -- "
            f"run it as ssh -o 'ProxyCommand={_prog()}' rather than directly."
        ) from e

    async def stdin_to_ws() -> None:
        try:
            while True:
                data = await reader.read(BUF_SIZE)
                if not data:
                    break
                await ws.send(data)
        except (asyncio.CancelledError, websockets.ConnectionClosed):
            pass

    async def ws_to_stdout() -> None:
        try:
            async for msg in ws:
                w_transport.write(msg if isinstance(msg, bytes) else msg.encode())
        except (asyncio.CancelledError, websockets.ConnectionClosed):
            pass

    tasks = [asyncio.create_task(stdin_to_ws()), asyncio.create_task(ws_to_stdout())]
    try:
        # Whichever side ends first ends the session; SSH tears down from there.
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        w_transport.close()


_STATUS_MESSAGES = {
    403: "relay rejected the token (403 Forbidden)",
    4003: "relay rejected the token",
    4029: "relay rate limit reached or server busy",
    4001: "target parameter missing or malformed (universal/cloudflare mode)",
    4002: "target host not allowed by the relay",
    426: "relay did not accept the WebSocket upgrade (check the URL path)",
    1008: "relay is misconfigured (RELAY_TOKEN not set on the server)",
    1011: "relay could not reach the target host",
}


def _report_error(e: Exception, url: str) -> None:
    """Translate a connection failure into a human-readable stderr message."""
    if isinstance(e, ConnectionRefusedError):
        print(f"Error: cannot reach relay at {url}", file=sys.stderr)
        return

    # The websockets API exposes the HTTP status differently across versions.
    code = getattr(e, "status_code", None)
    if code is None:
        response = getattr(e, "response", None)
        code = getattr(response, "status_code", None)
    if code is None:
        code = getattr(e, "code", None)

    if code in _STATUS_MESSAGES:
        print(f"Error: {_STATUS_MESSAGES[code]}", file=sys.stderr)
    elif code is not None:
        print(f"Error: relay returned status {code}", file=sys.stderr)
    else:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)


def _report_relay_close(ws) -> bool:
    """Print why the relay closed the tunnel. Returns True if it refused us."""
    code = getattr(ws, "close_code", None) if ws is not None else None
    if code is None or code in (1000, 1001):
        return False
    reason = _STATUS_MESSAGES.get(code)
    if not reason:
        detail = (getattr(ws, "close_reason", "") or "").strip()
        reason = f"relay closed the tunnel (code {code}{': ' + detail if detail else ''})"
    print(f"Error: {reason}", file=sys.stderr)
    return True


async def proxy() -> None:
    url, token = _get_config()

    # Send the token in the query string (some proxies strip auth headers) and
    # as a header (cleaner for backends that log query strings).
    sep = "&" if "?" in url else "?"
    auth_url = f"{url}{sep}token={token}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    _clear_proxy_env()
    ssl_ctx = _make_ssl_context() if auth_url.startswith("wss://") else None

    socket = None
    try:
        async with connect(
            auth_url,
            additional_headers=headers,
            ssl=ssl_ctx,
            ping_interval=30,
            ping_timeout=120,
            max_size=None,
            close_timeout=5,
            # Do not even offer permessage-deflate. SSH is encrypted and does
            # not compress, so deflate costs CPU on both ends to produce
            # slightly larger frames. Declining here also covers relays we do
            # not control, including the Cloudflare Worker path.
            compression=None,
        ) as ws:
            socket = ws
            await _run_tunnel(ws)
    except Exception as e:  # noqa: BLE001 - all failures become one stderr line
        # A relay rejection is the root cause even if the local teardown then
        # failed for its own reasons, so report that in preference.
        if not _report_relay_close(socket):
            _report_error(e, url)
        sys.exit(1)

    # The relay accepts the upgrade and *then* closes with an application code
    # when it refuses a request, so a rejected token looks like a successful
    # connect. Without this, ssh would see a silent EOF and no explanation.
    if _report_relay_close(socket):
        sys.exit(1)


def main() -> None:
    """Console-script entry point.

    A console script needs a named callable, so the asyncio.run() that used to
    sit under __main__ lives here and __main__ defers to it. Behaviour when the
    file is run directly is unchanged.
    """
    try:
        asyncio.run(proxy())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
