#!/usr/bin/env python3
"""Test suite for cowork-tunnel.

Exercises the code that actually ships: the relay scripts are imported for
unit tests and spawned as real subprocesses for integration tests. Nothing
here reimplements relay logic, so a bug in relay/*.py fails these tests.

Runs fully offline -- every target is a loopback address or an IP literal, so
no DNS resolution or outbound network access is required.

Usage:
  python3 tests/test_all.py
  python3 tests/test_all.py -v     # show per-test detail
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import inspect
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import types
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from urllib.parse import quote

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELAY_DIR = os.path.join(REPO, "relay")
CLIENT = os.path.join(REPO, "client", "ws_proxy.py")
CLIENT_DIR = os.path.join(REPO, "client")

# Add client dir to path so we can import http_proxy
sys.path.insert(0, CLIENT_DIR)

try:
    import websockets
    from websockets.asyncio.client import connect
except ImportError:
    print(
        "websockets is required to run the tests:\n"
        "  python3 -m venv .venv && . .venv/bin/activate\n"
        "  pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)

VERBOSE = "-v" in sys.argv
BANNER = b"SSH-2.0-MockSSHD_CoworkTunnel\r\n"
TOKEN = "test-token-2f8a1c"

_passed: list[str] = []
_failed: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        _passed.append(name)
        if VERBOSE:
            print(f"  [PASS] {name}" + (f" -- {detail}" if detail else ""))
    else:
        _failed.append((name, detail))
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Module loading (relay scripts are standalone files, not a package)
# ---------------------------------------------------------------------------
def load_relay(filename: str, env: dict[str, str]) -> types.ModuleType:
    """Import a relay script with a controlled environment.

    Relay config is read at module scope, so the environment must be in place
    before import and each configuration needs its own module instance.
    """
    saved = dict(os.environ)
    os.environ.update(env)
    try:
        name = f"_relay_{filename}_{len(saved)}_{abs(hash(frozenset(env.items())))}"
        spec = importlib.util.spec_from_file_location(name, os.path.join(RELAY_DIR, filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.environ.clear()
        os.environ.update(saved)


# ---------------------------------------------------------------------------
# Mock SSH servers
# ---------------------------------------------------------------------------
async def sshd_echo(reader, writer):
    """Send an SSH banner, then echo everything back."""
    writer.write(BANNER)
    await writer.drain()
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def sshd_hangup(reader, writer):
    """Send a banner then immediately drop the connection."""
    writer.write(BANNER)
    await writer.drain()
    await asyncio.sleep(0.1)
    writer.close()


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
_next_port = 24400


def alloc_port() -> int:
    global _next_port
    _next_port += 1
    return _next_port


class Relay:
    """A relay script running as a real subprocess."""

    def __init__(self, script: str, env: dict[str, str]):
        self.script = script
        self.env = dict(env)
        self.port = int(self.env["WS_PORT"])
        # universal.py serves the HTTP proxy on its own port. Every instance
        # gets a distinct one so concurrent relays in this suite cannot collide
        # on the default.
        if script == "universal.py":
            self.env.setdefault("PROXY_PORT", str(alloc_port()))
        self.proxy_port = int(self.env["PROXY_PORT"]) if "PROXY_PORT" in self.env else None
        self.proc = None
        # Populated on exit so tests can assert the relay logged no tracebacks.
        self.stderr_text = ""

    async def __aenter__(self):
        env = {**os.environ, "RELAY_TOKEN": TOKEN, **self.env}
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable,
            os.path.join(RELAY_DIR, self.script),
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        # Probe the LAST port the relay binds. universal.py binds the
        # WebSocket listener before the HTTP one, so a reachable proxy port
        # means both are up -- and probing the WebSocket port would open and
        # drop a connection without sending a request line, which websockets
        # 14.1 through 16.0 log a traceback for. That noise would defeat the
        # "relay logged no unhandled exceptions" assertion.
        wanted = [self.proxy_port] if self.proxy_port else [self.port]
        for _ in range(60):
            await asyncio.sleep(0.1)
            if self.proc.returncode is not None:
                err = (await self.proc.stderr.read()).decode()
                raise RuntimeError(f"{self.script} exited rc={self.proc.returncode}: {err}")
            try:
                for port in wanted:
                    _r, w = await asyncio.open_connection("127.0.0.1", port)
                    w.close()
                return self
            except OSError:
                continue
        raise RuntimeError(f"{self.script} never bound ports {wanted}")

    async def __aexit__(self, *_exc):
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self.proc and self.proc.stderr is not None:
            try:
                data = await asyncio.wait_for(self.proc.stderr.read(), timeout=5)
                self.stderr_text = data.decode("utf-8", errors="replace")
            except (asyncio.TimeoutError, ValueError):
                self.stderr_text = ""

    def url(self, query: str = "") -> str:
        base = f"ws://127.0.0.1:{self.port}/ssh?token={TOKEN}"
        return base + query


async def close_code(url: str, timeout: float = 5.0):
    """Connect and return the close code the relay responds with.

    Returns "open" if the relay kept the tunnel up instead of closing it.
    """
    try:
        async with connect(url, open_timeout=timeout) as ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=timeout)
                return "open"
            except websockets.ConnectionClosed as e:
                return e.code
            except asyncio.TimeoutError:
                return "open"
    except websockets.ConnectionClosed as e:
        return e.code
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Unit tests: target parsing
# ---------------------------------------------------------------------------
def test_target_parsing() -> None:
    print("\nTarget parsing (relay/universal.py):")
    uni = load_relay("universal.py", {"RELAY_TOKEN": TOKEN})
    parse = uni._parse_target

    valid = [
        ("example.com:22", ("example.com", 22)),
        ("example.com", ("example.com", 22)),
        ("1.2.3.4:2222", ("1.2.3.4", 2222)),
        ("1.2.3.4", ("1.2.3.4", 22)),
        ("[2001:db8::1]:22", ("2001:db8::1", 22)),
        ("[::1]", ("::1", 22)),
        ("2001:db8::1", ("2001:db8::1", 22)),
        ("host-name.sub.example.com:65535", ("host-name.sub.example.com", 65535)),
    ]
    for raw, want in valid:
        check(f"parse {raw!r}", parse(raw) == want, f"got {parse(raw)}, want {want}")

    invalid = [
        "example.com:0",
        "example.com:65536",
        "example.com:99999",
        "example.com:-1",
        "example.com:ssh",
        "",
        "   ",
        ":22",
        "[2001:db8::1",
        "[not-an-ip]:22",
        "bad host:22",
        "host/../evil:22",
        "-leadingdash.com",
    ]
    for raw in invalid:
        check(f"reject {raw!r}", parse(raw) is None, f"got {parse(raw)}")


def test_private_detection() -> None:
    print("\nPrivate address detection (relay/universal.py):")
    uni = load_relay("universal.py", {"RELAY_TOKEN": TOKEN})
    is_private = uni._is_private

    private = [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.5",
        "172.16.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",  # RFC 6598 CGNAT -- not covered by is_private alone
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ]
    for addr in private:
        check(f"private: {addr}", is_private(addr) is True)

    public = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "93.184.216.34"]
    for addr in public:
        check(f"public: {addr}", is_private(addr) is False)


def test_token_comparison() -> None:
    print("\nToken comparison (relay/standalone.py):")
    st = load_relay("standalone.py", {"RELAY_TOKEN": "correct-horse"})
    check("correct token accepted", st._token_valid("correct-horse") is True)
    check("wrong token rejected", st._token_valid("wrong-horse") is False)
    check("empty token rejected", st._token_valid("") is False)
    check("prefix of token rejected", st._token_valid("correct") is False)
    # A non-ASCII token must not raise; hmac.compare_digest rejects str inputs
    # that are not ASCII-only, so the implementation encodes first.
    try:
        st._token_valid("pässwörd")
        check("non-ASCII token does not raise", True)
    except Exception as e:  # noqa: BLE001
        check("non-ASCII token does not raise", False, f"{type(e).__name__}: {e}")


def test_allowlist_matching() -> None:
    print("\nAllowlist matching (relay/universal.py):")
    uni = load_relay(
        "universal.py",
        {"RELAY_TOKEN": TOKEN, "ALLOWED_HOSTS": "server1.com,192.168.1.5,10.0.0.0/8"},
    )
    check("exact hostname matches", uni._host_allowlisted("server1.com") is True)
    check("hostname match is case-insensitive", uni._host_allowlisted("Server1.COM") is True)
    check("exact private IP matches", uni._host_allowlisted("192.168.1.5") is True)
    check("IP inside allowed CIDR matches", uni._host_allowlisted("10.1.2.3") is True)
    check("unlisted host does not match", uni._host_allowlisted("evil.com") is False)
    check("IP outside CIDR does not match", uni._host_allowlisted("11.1.2.3") is False)


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------
async def test_standalone(sshd_port: int, hangup_port: int) -> None:
    print("\nStandalone relay (relay/standalone.py):")
    env = {
        "WS_PORT": str(alloc_port()),
        "SSH_PORT": str(sshd_port),
        "RATE_LIMIT": "1000",
        "MAX_CONNECTIONS": "10",
    }
    async with Relay("standalone.py", env) as relay:
        # Auth
        bad = await close_code(f"ws://127.0.0.1:{relay.port}/ssh?token=WRONG")
        check("wrong token rejected with 4003", bad == 4003, f"got {bad}")
        none = await close_code(f"ws://127.0.0.1:{relay.port}/ssh")
        check("missing token rejected with 4003", none == 4003, f"got {none}")

        # Data flow
        try:
            async with connect(relay.url(), open_timeout=5) as ws:
                banner = await asyncio.wait_for(ws.recv(), timeout=5)
                banner = banner if isinstance(banner, bytes) else banner.encode()
                check("SSH banner relayed", banner.startswith(b"SSH-2.0"), banner.decode().strip())
                await ws.send(b"round-trip-payload\n")
                echo = await asyncio.wait_for(ws.recv(), timeout=5)
                echo = echo if isinstance(echo, bytes) else echo.encode()
                check("echo round-trip intact", echo == b"round-trip-payload\n")

                # Larger payload, to exercise chunking rather than a single frame
                blob = bytes(range(256)) * 512  # 128 KiB
                await ws.send(blob)
                received = b""
                while len(received) < len(blob):
                    chunk = await asyncio.wait_for(ws.recv(), timeout=10)
                    received += chunk if isinstance(chunk, bytes) else chunk.encode()
                check("128 KiB payload round-trips byte-exact", received == blob,
                      f"got {len(received)} of {len(blob)} bytes")
        except Exception as e:  # noqa: BLE001
            check("standalone data flow", False, f"{type(e).__name__}: {e}")

    # Half-close: the target hangs up, so the relay must close the WebSocket.
    # Regression test -- this previously hung until the client gave up, leaking
    # the connection slot.
    env2 = {"WS_PORT": str(alloc_port()), "SSH_PORT": str(hangup_port), "RATE_LIMIT": "1000"}
    async with Relay("standalone.py", env2) as relay:
        try:
            async with connect(relay.url(), open_timeout=5) as ws:
                await asyncio.wait_for(ws.recv(), timeout=5)  # banner
                try:
                    await asyncio.wait_for(ws.recv(), timeout=6)
                    check("relay closes tunnel when target hangs up", False, "unexpected data")
                except websockets.ConnectionClosed:
                    check("relay closes tunnel when target hangs up", True)
                except asyncio.TimeoutError:
                    check(
                        "relay closes tunnel when target hangs up",
                        False,
                        "hung: tunnel stayed open after target closed",
                    )
        except Exception as e:  # noqa: BLE001
            check("half-close handling", False, f"{type(e).__name__}: {e}")


async def test_limits(sshd_port: int) -> None:
    print("\nConnection limits (relay/standalone.py):")
    env = {"WS_PORT": str(alloc_port()), "SSH_PORT": str(sshd_port), "RATE_LIMIT": "3",
           "MAX_CONNECTIONS": "10"}
    async with Relay("standalone.py", env) as relay:
        codes = [await close_code(relay.url(), timeout=3) for _ in range(6)]
        check("rate limit returns 4029 once exceeded", 4029 in codes, f"codes={codes}")
        check("rate limit allows traffic below the threshold", codes[0] != 4029, f"first={codes[0]}")

    env = {"WS_PORT": str(alloc_port()), "SSH_PORT": str(sshd_port), "RATE_LIMIT": "1000",
           "MAX_CONNECTIONS": "1"}
    async with Relay("standalone.py", env) as relay:
        held = await connect(relay.url(), open_timeout=5)
        try:
            await asyncio.wait_for(held.recv(), timeout=5)  # banner; slot now held
            second = await close_code(relay.url(), timeout=3)
            check("max connections returns 4029", second == 4029, f"got {second}")
        finally:
            await held.close()


async def test_universal(sshd_port: int) -> None:
    print("\nUniversal relay (relay/universal.py):")

    # Default posture: no allowlist, no private blocking -- any target allowed.
    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000"}
    async with Relay("universal.py", env) as relay:
        bad = await close_code(f"ws://127.0.0.1:{relay.port}/ssh?token=WRONG&target=1.2.3.4:22")
        check("wrong token rejected with 4003", bad == 4003, f"got {bad}")

        missing = await close_code(relay.url())
        check("missing target rejected with 4001", missing == 4001, f"got {missing}")

        for raw, label in [
            ("1.2.3.4:99999", "out-of-range port"),
            ("1.2.3.4:0", "port zero"),
            ("bad host:22", "malformed hostname"),
        ]:
            code = await close_code(relay.url(f"&target={quote(raw, safe='')}"))
            check(f"{label} rejected with 4001", code == 4001, f"target={raw!r} got {code}")

        # The whole point of the universal relay: reach any target, including
        # hosts on the relay's own private network.
        try:
            async with connect(relay.url(f"&target=127.0.0.1:{sshd_port}"), open_timeout=5) as ws:
                banner = await asyncio.wait_for(ws.recv(), timeout=5)
                banner = banner if isinstance(banner, bytes) else banner.encode()
                check(
                    "private target reachable by default",
                    banner.startswith(b"SSH-2.0"),
                    banner.decode().strip(),
                )
                await ws.send(b"universal-echo\n")
                echo = await asyncio.wait_for(ws.recv(), timeout=5)
                echo = echo if isinstance(echo, bytes) else echo.encode()
                check("universal echo round-trip", echo == b"universal-echo\n")
        except Exception as e:  # noqa: BLE001
            check("universal data flow to private target", False, f"{type(e).__name__}: {e}")

    # Allowlisted private host must be reachable. Regression test: the private
    # address guard used to run first and rejected it unconditionally, so the
    # documented ALLOWED_HOSTS example could never work.
    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000",
           "ALLOWED_HOSTS": "127.0.0.1", "BLOCK_PRIVATE": "1"}
    async with Relay("universal.py", env) as relay:
        try:
            async with connect(relay.url(f"&target=127.0.0.1:{sshd_port}"), open_timeout=5) as ws:
                banner = await asyncio.wait_for(ws.recv(), timeout=5)
                banner = banner if isinstance(banner, bytes) else banner.encode()
                check(
                    "allowlist overrides BLOCK_PRIVATE for a listed host",
                    banner.startswith(b"SSH-2.0"),
                    banner.decode().strip(),
                )
        except Exception as e:  # noqa: BLE001
            check("allowlist overrides BLOCK_PRIVATE", False, f"{type(e).__name__}: {e}")

        off = await close_code(relay.url("&target=1.2.3.4:22"))
        check("unlisted target rejected with 4002", off == 4002, f"got {off}")

    # BLOCK_PRIVATE with no allowlist must refuse private targets.
    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000", "BLOCK_PRIVATE": "1"}
    async with Relay("universal.py", env) as relay:
        code = await close_code(relay.url(f"&target=127.0.0.1:{sshd_port}"))
        check("BLOCK_PRIVATE refuses loopback with 4002", code == 4002, f"got {code}")
        code = await close_code(relay.url("&target=169.254.169.254:80"))
        check("BLOCK_PRIVATE refuses link-local with 4002", code == 4002, f"got {code}")


async def test_ws_proxy_client(sshd_port: int) -> None:
    print("\nClient (client/ws_proxy.py):")
    env = {"WS_PORT": str(alloc_port()), "SSH_PORT": str(sshd_port), "RATE_LIMIT": "1000"}
    async with Relay("standalone.py", env) as relay:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            CLIENT,
            f"ws://127.0.0.1:{relay.port}/ssh",
            TOKEN,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            # stdout is the SSH data channel: the very first bytes must be the
            # banner, with no diagnostics or installer chatter ahead of them.
            head = await asyncio.wait_for(proc.stdout.readexactly(len(BANNER)), timeout=10)
            check("first stdout bytes are the SSH banner", head == BANNER, repr(head[:40]))

            proc.stdin.write(b"client-echo-test\n")
            await proc.stdin.drain()
            echo = await asyncio.wait_for(proc.stdout.readexactly(17), timeout=10)
            check("client echo round-trip", echo == b"client-echo-test\n", repr(echo))
        except asyncio.TimeoutError:
            err = b""
            try:
                err = await asyncio.wait_for(proc.stderr.read(2048), timeout=2)
            except asyncio.TimeoutError:
                pass
            check("ws_proxy.py tunnels data", False, f"timeout; stderr={err.decode()[:300]}")
        except Exception as e:  # noqa: BLE001
            check("ws_proxy.py tunnels data", False, f"{type(e).__name__}: {e}")
        finally:
            proc.kill()
            await proc.wait()

    # A bad token must produce a clean diagnostic on stderr and a non-zero exit,
    # never a partial stream on stdout.
    env = {"WS_PORT": str(alloc_port()), "SSH_PORT": str(sshd_port), "RATE_LIMIT": "1000"}
    async with Relay("standalone.py", env) as relay:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            CLIENT,
            f"ws://127.0.0.1:{relay.port}/ssh",
            "WRONG-TOKEN",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
            check("bad token exits non-zero", proc.returncode != 0, f"rc={proc.returncode}")
            check("bad token writes nothing to stdout", out == b"", repr(out[:60]))
            check("bad token explains itself on stderr", b"token" in err.lower(),
                  err.decode()[:120].strip())
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            check("bad token handled cleanly", False, "client hung instead of exiting")

    # The Cloudflare Worker refuses before the upgrade with an HTTP status and a
    # text body: 403 "Forbidden" for a bad token, 403 with a reason for a target
    # outside ALLOWED_HOSTS or blocked by BLOCK_PRIVATE, 400 for a bad target.
    # The client must pass the reason on rather than blaming the token.
    cases = [
        (403, b"Forbidden", "relay rejected the token", "403 Forbidden is reported as a rejected token"),
        (403, b"Target not in allowlist", "relay refused the request: Target not in allowlist",
         "403 for a refused target shows the relay's reason, not 'token'"),
        (403, b"Private/loopback addresses not allowed",
         "relay refused the request: Private/loopback addresses not allowed",
         "403 from BLOCK_PRIVATE shows the relay's reason"),
        (400, b"Invalid target", "relay refused the request: Invalid target", "400 shows the relay's reason"),
        (403, b"bad\x1b[31m\xe2\x80\xaeevil", "relay refused the request: bad [31m evil",
         "control and bidi characters in the reason are blanked"),
    ]
    for status, body, expected, label in cases:
        async def refuse(reader, writer, status=status, body=body):
            await reader.readuntil(b"\r\n\r\n")
            reason = "Forbidden" if status == 403 else "Bad Request"
            writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(refuse, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, CLIENT, f"ws://127.0.0.1:{port}/?target=example.com:22", TOKEN,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
            text = err.decode(errors="replace").strip()
            check(label, proc.returncode != 0 and out == b"" and expected in text, text[:160])
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            check(label, False, "client hung instead of exiting")
        finally:
            server.close()
            await server.wait_closed()


# ---------------------------------------------------------------------------
# Mock HTTP server for proxy tests
# ---------------------------------------------------------------------------
class _MockHTTPHandler(BaseHTTPRequestHandler):
    """A simple HTTP handler for testing the HTTP proxy path."""

    def log_message(self, format, *args):
        pass  # suppress log output during tests

    def do_GET(self):
        if self.path == "/json":
            body = json.dumps({"greeting": "hello", "source": "mock"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Custom-Header", "test-value")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/error500":
            body = b"Internal Server Error"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/echo-headers":
            # Return the received headers as JSON
            headers_dict = {k: v for k, v in self.headers.items()}
            body = json.dumps(headers_dict).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/big":
            # Deterministic filler, large enough to cross several socket reads.
            body = (b"cowork-tunnel-" * 4096) * 32  # ~1.8 MiB
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/json")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/redirect-evil":
            # A cooperative-looking target that tries to bounce the relay onto
            # its own filesystem.
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/cookies":
            # Two Set-Cookie headers, one carrying a comma inside its Expires
            # date -- exactly the case that comma-joining corrupts.
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "a=1; Path=/")
            self.send_header(
                "Set-Cookie", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/"
            )
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/dupe-headers":
            body = b"ok"
            self.send_response(200)
            self.send_header("X-Multi", "one")
            self.send_header("X-Multi", "two")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        if self.path == "/echo":
            # Echo back the body with the content-type and a custom header
            self.send_response(200)
            ct = self.headers.get("Content-Type", "application/octet-stream")
            self.send_header("Content-Type", ct)
            self.send_header("X-Echo", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            resp = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)


def start_mock_http_server(port: int) -> HTTPServer:
    """Start a mock HTTP server in a background thread."""
    server = HTTPServer(("127.0.0.1", port), _MockHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# HTTP Proxy unit tests
# ---------------------------------------------------------------------------
def test_http_proxy_url_normalization() -> None:
    print("\nHTTP proxy URL normalization (client/http_proxy.py):")
    from http_proxy import _normalize_relay_url

    cases = [
        ("wss://relay.example.com/ssh?target=host:22&token=xxx",
         "https://relay.example.com/proxy"),
        ("wss://relay.example.com/ssh",
         "https://relay.example.com/proxy"),
        ("ws://localhost:8765/ssh",
         "http://localhost:8765/proxy"),
        ("https://relay.example.com",
         "https://relay.example.com/proxy"),
        ("https://relay.example.com/some/path",
         "https://relay.example.com/proxy"),
        ("http://127.0.0.1:9000",
         "http://127.0.0.1:9000/proxy"),
    ]
    for raw, want in cases:
        got = _normalize_relay_url(raw)
        check(f"normalize {raw!r}", got == want, f"got {got!r}, want {want!r}")


def test_http_proxy_header_stripping() -> None:
    print("\nHTTP proxy hop-by-hop header stripping (client/http_proxy.py):")
    from http_proxy import _strip_hop_by_hop

    headers = {
        "Content-Type": "application/json",
        "Connection": "keep-alive",
        "Authorization": "Bearer token",
        "Transfer-Encoding": "chunked",
        "X-Custom": "value",
        "Keep-Alive": "timeout=5",
    }
    stripped = _strip_hop_by_hop(headers)
    check("keeps Content-Type", "Content-Type" in stripped)
    check("keeps Authorization", "Authorization" in stripped)
    check("keeps X-Custom", "X-Custom" in stripped)
    check("strips Connection", "Connection" not in stripped)
    check("strips Transfer-Encoding", "Transfer-Encoding" not in stripped)
    check("strips Keep-Alive", "Keep-Alive" not in stripped)


# ---------------------------------------------------------------------------
# HTTP Proxy integration tests (through universal relay)
# ---------------------------------------------------------------------------
def _proxy_request(relay_port: int, envelope: dict, token: str = TOKEN) -> dict:
    """Send a raw HTTP POST /proxy to the relay and return the parsed response."""
    import urllib.request
    import urllib.error

    payload = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{relay_port}/proxy",
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return {"_http_status": e.code, **json.loads(body)}
        except (json.JSONDecodeError, ValueError):
            return {"_http_status": e.code, "_body": body.decode("utf-8", errors="replace")}


def _proxy_request_raw(relay_port: int, envelope: dict, token: str = TOKEN):
    """Send a raw HTTP request and return (http_status, parsed_body)."""
    import urllib.request
    import urllib.error

    payload = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{relay_port}/proxy",
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"_body": body.decode("utf-8", errors="replace")}


async def test_http_proxy(sshd_port: int) -> None:
    print("\nHTTP proxy through universal relay:")

    mock_http_port = alloc_port()
    mock_server = start_mock_http_server(mock_http_port)

    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000"}
    try:
        async with Relay("universal.py", env) as relay:
            # Test 1: Auth rejection on bad token
            status, resp = await asyncio.to_thread(
                _proxy_request_raw, relay.proxy_port,
                {"url": f"http://127.0.0.1:{mock_http_port}/json", "method": "GET"},
                "WRONG-TOKEN",
            )
            check("HTTP proxy rejects bad token with 401", status == 401,
                  f"got status {status}")

            # Test 2: Auth rejection on missing token
            status, resp = await asyncio.to_thread(
                _proxy_request_raw, relay.proxy_port,
                {"url": f"http://127.0.0.1:{mock_http_port}/json", "method": "GET"},
                "",
            )
            check("HTTP proxy rejects missing token with 401", status == 401,
                  f"got status {status}")

            # Test 3: Successful GET with JSON response
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {"url": f"http://127.0.0.1:{mock_http_port}/json", "method": "GET"},
            )
            check("HTTP proxy GET returns status 200", result.get("status") == 200,
                  f"got {result.get('status')}")
            body = base64.b64decode(result.get("body_b64", ""))
            parsed = json.loads(body)
            check("HTTP proxy GET body round-trip", parsed.get("greeting") == "hello",
                  f"body={parsed}")
            check("HTTP proxy GET preserves response headers",
                  result.get("headers", {}).get("X-Custom-Header") == "test-value",
                  f"headers={result.get('headers')}")

            # Test 4: POST with JSON body
            post_body = json.dumps({"message": "test post"})
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"http://127.0.0.1:{mock_http_port}/echo",
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": post_body,
                },
            )
            check("HTTP proxy POST returns status 200", result.get("status") == 200,
                  f"got {result.get('status')}")
            resp_body = base64.b64decode(result.get("body_b64", ""))
            check("HTTP proxy POST body echoed correctly", resp_body == post_body.encode(),
                  f"got {resp_body!r}")

            # Test 5: Binary body via body_b64
            binary_data = bytes(range(256))
            b64_data = base64.b64encode(binary_data).decode("ascii")
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"http://127.0.0.1:{mock_http_port}/echo",
                    "method": "POST",
                    "headers": {"Content-Type": "application/octet-stream"},
                    "body_b64": b64_data,
                },
            )
            check("HTTP proxy binary body_b64 returns 200", result.get("status") == 200,
                  f"got {result.get('status')}")
            resp_body = base64.b64decode(result.get("body_b64", ""))
            check("HTTP proxy binary body round-trip", resp_body == binary_data,
                  f"got {len(resp_body)} bytes, want {len(binary_data)}")

            # Test 6: Target error (500) passes through
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {"url": f"http://127.0.0.1:{mock_http_port}/error500", "method": "GET"},
            )
            check("HTTP proxy passes through 500 status", result.get("status") == 500,
                  f"got {result.get('status')}")

            # Test 7: Unreachable target returns 502 with a JSON error body
            unreachable_port = alloc_port()  # Nothing listening
            status, result = await asyncio.to_thread(
                _proxy_request_raw, relay.proxy_port,
                {"url": f"http://127.0.0.1:{unreachable_port}/anything", "method": "GET"},
            )
            check("HTTP proxy returns 502 for unreachable target", status == 502,
                  f"got status {status}")
            check("HTTP proxy 502 carries a JSON error", "error" in result,
                  f"result={result}")

            # Test 8: Bad JSON returns 400
            import urllib.request
            import urllib.error
            bad_req = urllib.request.Request(
                f"http://127.0.0.1:{relay.proxy_port}/proxy",
                data=b"not-json",
                method="POST",
            )
            bad_req.add_header("Content-Type", "application/json")
            bad_req.add_header("Authorization", f"Bearer {TOKEN}")
            try:
                with urllib.request.urlopen(bad_req, timeout=10) as resp:
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            check("HTTP proxy rejects bad JSON with 400", status == 400,
                  f"got {status}")

            # Test 9: Missing required fields returns 400
            status, resp = await asyncio.to_thread(
                _proxy_request_raw, relay.proxy_port,
                {"url": f"http://127.0.0.1:{mock_http_port}/json"},  # missing method
            )
            check("HTTP proxy rejects missing 'method' with 400", status == 400,
                  f"got status {status}")

            # Test 10: Headers forwarded to target
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"http://127.0.0.1:{mock_http_port}/echo-headers",
                    "method": "GET",
                    "headers": {"X-Test-Header": "forwarded-value"},
                },
            )
            resp_body = base64.b64decode(result.get("body_b64", ""))
            echoed_headers = json.loads(resp_body)
            check("HTTP proxy forwards custom headers to target",
                  echoed_headers.get("X-Test-Header") == "forwarded-value",
                  f"echoed={echoed_headers}")

            # Test 11: WebSocket SSH still works after HTTP proxy usage
            try:
                async with connect(
                    relay.url(f"&target=127.0.0.1:{sshd_port}"), open_timeout=5
                ) as ws:
                    banner = await asyncio.wait_for(ws.recv(), timeout=5)
                    banner = banner if isinstance(banner, bytes) else banner.encode()
                    check(
                        "SSH still works after HTTP proxy requests",
                        banner.startswith(b"SSH-2.0"),
                        banner.decode().strip(),
                    )
            except Exception as e:
                check("SSH still works after HTTP proxy requests", False,
                      f"{type(e).__name__}: {e}")

    finally:
        mock_server.shutdown()


async def _raw_request(port: int, request: bytes,
                       read_timeout: float = 5.0) -> tuple[bytes, bool]:
    """Send raw bytes to the relay.

    Returns (response_bytes, server_closed). server_closed is True only if the
    relay hung up on its own, which is what `Connection: close` promises.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    data = b""
    closed = False
    try:
        writer.write(request)
        await writer.drain()
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=read_timeout)
            if not chunk:
                closed = True
                break
            data += chunk
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    return data, closed


def _status_line(response: bytes) -> int:
    """Extract the numeric status from a raw HTTP response."""
    try:
        return int(response.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def _post_proxy(envelope: dict, token: str = TOKEN,
                content_length: int | None = None,
                extra_headers: bytes = b"") -> bytes:
    """Build a raw POST /proxy request."""
    payload = json.dumps(envelope).encode()
    length = len(payload) if content_length is None else content_length
    return (
        b"POST /proxy HTTP/1.1\r\nHost: relay\r\n"
        + f"Authorization: Bearer {token}\r\n".encode()
        + b"Content-Type: application/json\r\n"
        + f"Content-Length: {length}\r\n".encode()
        + extra_headers
        + b"\r\n"
        + payload
    )


async def test_http_proxy_hardening(sshd_port: int) -> None:
    """Malformed, oversized and hostile requests must fail cleanly.

    Every case here reached a hang, a leaked connection or a stack trace before
    the HTTP path was rewritten, so each one is a regression guard.
    """
    print("\nHTTP proxy hardening (relay/universal.py):")

    mock_http_port = alloc_port()
    mock_server = start_mock_http_server(mock_http_port)
    target = f"http://127.0.0.1:{mock_http_port}/json"

    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000", "PROXY_RATE_LIMIT": "1000"}
    try:
        async with Relay("universal.py", env) as relay:
            # The relay promises Connection: close and must deliver it. A relay
            # that answers but never hangs up leaks a descriptor per request.
            resp, closed = await _raw_request(
                relay.proxy_port, _post_proxy({"url": target, "method": "GET"})
            )
            check("proxy response closes the connection", closed,
                  "relay answered but left the socket open")
            check("proxy response is 200", _status_line(resp) == 200,
                  f"got {_status_line(resp)}")

            # Non-HTTP schemes would turn the proxy into a file reader.
            for scheme_url, label in [
                ("file:///etc/passwd", "file://"),
                ("ftp://127.0.0.1/x", "ftp://"),
                ("data:text/plain,hello", "data:"),
            ]:
                resp, _ = await _raw_request(
                    relay.proxy_port, _post_proxy({"url": scheme_url, "method": "GET"})
                )
                status = _status_line(resp)
                check(f"proxy refuses {label} with 400", status == 400, f"got {status}")
                check(f"proxy leaks nothing for {label}",
                      b"root:" not in resp and b"/bin/" not in resp,
                      "response contained file content")

            # A redirect is followed by the relay, so the scheme guard has to
            # hold on the redirect target too, not just the requested URL.
            resp, _ = await _raw_request(
                relay.proxy_port,
                _post_proxy({"url": f"http://127.0.0.1:{mock_http_port}/redirect-evil",
                             "method": "GET"}),
                read_timeout=8.0,
            )
            check("redirect to file:// does not leak file contents",
                  b"root:" not in resp and b"/bin/" not in resp,
                  f"got {resp[:160]!r}")

            # Malformed envelopes must produce an answer, not a hang.
            for envelope, label in [
                ({"url": target, "method": "POST", "body_b64": "!!!not-base64!!!"},
                 "invalid body_b64"),
                ({"url": target, "method": "GET HTTP/1.1"}, "invalid method"),
                ({"url": "not-a-url", "method": "GET"}, "unparseable url"),
                ({"url": target, "method": "GET", "headers": {"X-Bad": "a\r\nInjected: 1"}},
                 "header injection"),
                ({"url": target, "method": "GET", "headers": {"Bad Name": "v"}},
                 "invalid header name"),
            ]:
                resp, closed = await _raw_request(relay.proxy_port, _post_proxy(envelope))
                status = _status_line(resp)
                check(f"proxy rejects {label} with 400", status == 400, f"got {status}")
                check(f"proxy answers at all for {label}", bool(resp), "no response")

            # A JSON array is valid JSON but not a valid envelope.
            resp, _ = await _raw_request(
                relay.proxy_port,
                b"POST /proxy HTTP/1.1\r\nHost: relay\r\n"
                + f"Authorization: Bearer {TOKEN}\r\n".encode()
                + b"Content-Length: 2\r\n\r\n[]",
            )
            check("proxy rejects non-object envelope with 400",
                  _status_line(resp) == 400, f"got {_status_line(resp)}")

            # A bad Content-Length used to raise ValueError inside the protocol
            # and drop the connection with no response at all.
            resp, _ = await _raw_request(
                relay.proxy_port,
                b"POST /proxy HTTP/1.1\r\nHost: relay\r\n"
                + f"Authorization: Bearer {TOKEN}\r\n".encode()
                + b"Content-Length: abc\r\n\r\n{}",
            )
            check("proxy rejects non-numeric Content-Length with 400",
                  _status_line(resp) == 400, f"got {_status_line(resp)}")

            resp, _ = await _raw_request(
                relay.proxy_port,
                b"POST /proxy HTTP/1.1\r\nHost: relay\r\n"
                + f"Authorization: Bearer {TOKEN}\r\n".encode()
                + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            )
            check("proxy rejects chunked encoding with 411",
                  _status_line(resp) == 411, f"got {_status_line(resp)}")

            # Routing
            resp, _ = await _raw_request(
                relay.proxy_port, b"GET /proxy HTTP/1.1\r\nHost: relay\r\n\r\n"
            )
            check("GET /proxy returns 405", _status_line(resp) == 405,
                  f"got {_status_line(resp)}")

            resp, _ = await _raw_request(
                relay.proxy_port, b"GET /nope HTTP/1.1\r\nHost: relay\r\n\r\n"
            )
            check("unknown path on the proxy port returns 404",
                  _status_line(resp) == 404, f"got {_status_line(resp)}")

            resp, closed = await _raw_request(
                relay.proxy_port, b"HEAD /health HTTP/1.1\r\nHost: relay\r\n\r\n"
            )
            check("HEAD /health returns 200", _status_line(resp) == 200,
                  f"got {_status_line(resp)}")
            check("health response closes the connection", closed)
            # RFC 9110: a HEAD response carries the GET's headers and no body.
            # nginx hides this in the documented deployment; a direct connection
            # does not.
            head_end = resp.find(b"\r\n\r\n")
            check("HEAD /health sends no body",
                  head_end != -1 and resp[head_end + 4:] == b"",
                  f"body={resp[head_end + 4:][:60]!r}")
            check("HEAD /health still declares Content-Length",
                  b"content-length:" in resp.lower(), f"got {resp[:120]!r}")

            resp, _ = await _raw_request(
                relay.proxy_port, b"GET /health HTTP/1.1\r\nHost: relay\r\n\r\n"
            )
            check("GET /health does send a body",
                  resp.split(b"\r\n\r\n", 1)[-1].startswith(b"{"),
                  f"got {resp[-80:]!r}")

            resp, _ = await _raw_request(
                relay.proxy_port,
                b"GET /health HTTP/1.1\r\nHost: relay\r\nX-Pad: "
                + b"A" * 40000 + b"\r\n\r\n",
            )
            check("oversized request head returns 431", _status_line(resp) == 431,
                  f"got {_status_line(resp)}")

            # Expect: 100-continue is what curl sends ahead of a large body.
            resp, _ = await _raw_request(
                relay.proxy_port,
                _post_proxy({"url": target, "method": "GET"},
                            extra_headers=b"Expect: 100-continue\r\n"),
            )
            check("Expect: 100-continue is honoured",
                  b"100 Continue" in resp and b"200 OK" in resp,
                  f"got {resp[:80]!r}")

        check("relay logged no unhandled exceptions",
              "Task exception was never retrieved" not in relay.stderr_text
              and "Traceback" not in relay.stderr_text,
              relay.stderr_text[-300:])

        # Port separation, on its own relay. websockets logs a traceback of its
        # own when handed a POST (14.1 through 16.0 raise "unsupported HTTP
        # method"), which is the library's noise rather than ours -- keeping it
        # off the relay above lets that log-cleanliness check stay strict.
        env = {"WS_PORT": str(alloc_port()), "PROXY_RATE_LIMIT": "1000"}
        async with Relay("universal.py", env) as split:
            # The SSH port is websockets' own listener; a plain GET there must
            # still get the documented 426, matching the Cloudflare Worker.
            resp, _ = await _raw_request(
                split.port, b"GET /ssh HTTP/1.1\r\nHost: relay\r\n\r\n"
            )
            check("plain GET on the SSH port returns 426",
                  _status_line(resp) == 426, f"got {_status_line(resp)}")

            resp, _ = await _raw_request(
                split.port, _post_proxy({"url": target, "method": "GET"})
            )
            check("SSH port does not serve /proxy", _status_line(resp) != 200,
                  f"got {_status_line(resp)}")

            resp, _ = await _raw_request(
                split.proxy_port,
                b"GET /ssh HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n",
            )
            check("proxy port does not serve WebSocket upgrades",
                  _status_line(resp) == 404, f"got {_status_line(resp)}")

        # Limits need their own relay so the thresholds can be driven down to
        # something a test can reach cheaply.
        env = {
            "WS_PORT": str(alloc_port()),
            "RATE_LIMIT": "1000",
            "PROXY_RATE_LIMIT": "3",
            "MAX_PROXY_BODY": "2048",
            "HEAD_TIMEOUT": "1",
        }
        async with Relay("universal.py", env) as limited:
            oversized = {"url": target, "method": "POST", "body_b64":
                         base64.b64encode(b"x" * 4096).decode()}
            resp, closed = await _raw_request(limited.proxy_port, _post_proxy(oversized))
            check("oversized body returns a readable 413",
                  _status_line(resp) == 413, f"got {_status_line(resp)}")
            check("413 arrives as JSON, not a reset", b'"error"' in resp,
                  f"got {resp[:120]!r}")

            statuses = []
            for _ in range(5):
                resp, _ = await _raw_request(
                    limited.proxy_port, _post_proxy({"url": target, "method": "GET"})
                )
                statuses.append(_status_line(resp))
            check("proxy rate limit returns 429", 429 in statuses, f"got {statuses}")

            # A connection that opens and says nothing must not be held forever.
            start = asyncio.get_running_loop().time()
            reader, writer = await asyncio.open_connection("127.0.0.1", limited.proxy_port)
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=6)
                elapsed = asyncio.get_running_loop().time() - start
                check("idle connection is timed out", elapsed < 5,
                      f"took {elapsed:.1f}s")
                check("idle connection gets 408", _status_line(data) == 408,
                      f"got {_status_line(data)}")
            except asyncio.TimeoutError:
                check("idle connection is timed out", False, "still open after 6s")
                check("idle connection gets 408", False, "no response")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
    finally:
        mock_server.shutdown()


def test_env_parsing() -> None:
    """Garbage in the environment must not crash a relay at import time.

    A typo in a systemd env file used to take standalone.py down with an
    unhandled ValueError before it could log anything useful.
    """
    print("\nEnvironment parsing (relay/*.py):")

    for script, keys in [
        ("universal.py", ["WS_PORT", "PROXY_PORT", "MAX_CONNECTIONS", "RATE_LIMIT"]),
        ("standalone.py", ["WS_PORT", "SSH_PORT", "MAX_CONNECTIONS", "RATE_LIMIT"]),
    ]:
        defaults = load_relay(script, {"RELAY_TOKEN": TOKEN})
        for bad in ("not-a-number", "", "-5", "0"):
            try:
                mod = load_relay(script, {"RELAY_TOKEN": TOKEN, **{k: bad for k in keys}})
            except Exception as e:  # noqa: BLE001 - the point is that it must not raise
                check(f"{script} survives {keys[0]}={bad!r}", False,
                      f"{type(e).__name__}: {e}")
                continue
            ok = all(
                isinstance(getattr(mod, k), int) and getattr(mod, k) == getattr(defaults, k)
                for k in keys
            )
            check(f"{script} falls back to defaults on {bad!r}", ok,
                  {k: getattr(mod, k) for k in keys})

        good = load_relay(script, {"RELAY_TOKEN": TOKEN, keys[0]: "9999"})
        check(f"{script} still honours a valid {keys[0]}",
              getattr(good, keys[0]) == 9999, f"got {getattr(good, keys[0])}")


async def test_no_permessage_deflate(sshd_port: int) -> None:
    """The relays must decline permessage-deflate.

    websockets negotiates it by default, and this tunnel carries SSH -- an
    encrypted stream that cannot compress. Leaving it on cost roughly 17x
    throughput (12.5 MiB/s against 220 MiB/s on 100 MiB of random data) to
    produce slightly larger frames. Asserted against the handshake response so
    the check does not depend on library internals.
    """
    print("\nWebSocket compression (relay/*.py):")

    handshake = (
        b"GET /ssh HTTP/1.1\r\n"
        b"Host: relay\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Extensions: permessage-deflate\r\n"
        b"\r\n"
    )

    for script, env in [
        ("universal.py", {"WS_PORT": str(alloc_port())}),
        ("standalone.py", {"WS_PORT": str(alloc_port()), "SSH_PORT": str(sshd_port)}),
    ]:
        async with Relay(script, env) as relay:
            resp, _ = await _raw_request(relay.port, handshake, read_timeout=3.0)
            lowered = resp.lower()
            check(f"{script} completes the handshake",
                  b"101" in resp.split(b"\r\n")[0], f"got {resp.split(b'!r')[0][:60]!r}")
            check(f"{script} declines permessage-deflate",
                  b"sec-websocket-extensions" not in lowered,
                  f"got {resp[:200]!r}")


async def test_upstream_tls_verification() -> None:
    """The relay must verify upstream certificates unless told not to.

    The relay is the hop that carries forwarded credentials onto the real
    internet, so a silent return to CERT_NONE would be a security regression
    with no visible symptom. Needs the openssl CLI to mint a throwaway cert; if
    it is unavailable the checks are reported as skipped rather than passed.
    """
    print("\nUpstream TLS verification (relay/universal.py):")

    if shutil.which("openssl") is None:
        print("  [SKIP] openssl not available; cannot mint a self-signed cert")
        return

    with tempfile.TemporaryDirectory() as tmp:
        cert = os.path.join(tmp, "cert.pem")
        key = os.path.join(tmp, "key.pem")
        proc = await asyncio.create_subprocess_exec(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
            "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        if await proc.wait() != 0:
            print("  [SKIP] openssl could not generate a test certificate")
            return

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        https_port = alloc_port()
        server = HTTPServer(("127.0.0.1", https_port), _MockHTTPHandler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        target = {"url": f"https://localhost:{https_port}/json", "method": "GET"}
        try:
            env = {"WS_PORT": str(alloc_port()), "PROXY_RATE_LIMIT": "1000"}
            async with Relay("universal.py", env) as relay:
                status, result = await asyncio.to_thread(
                    _proxy_request_raw, relay.proxy_port, target
                )
                check("self-signed upstream is refused by default", status == 502,
                      f"got status {status}")
                check("refusal names the certificate as the cause",
                      "CERTIFICATE_VERIFY_FAILED" in str(result.get("error", "")),
                      f"got {result.get('error')}")

            env = {
                "WS_PORT": str(alloc_port()),
                "PROXY_RATE_LIMIT": "1000",
                "INSECURE_UPSTREAM_TLS": "1",
            }
            async with Relay("universal.py", env) as relay:
                result = await asyncio.to_thread(_proxy_request, relay.proxy_port, target)
                check("INSECURE_UPSTREAM_TLS=1 allows it through",
                      result.get("status") == 200, f"got {result.get('status')}")
        finally:
            server.shutdown()


async def test_http_proxy_fidelity(sshd_port: int) -> None:
    """Large bodies, redirects, cookies and duplicate headers survive the trip."""
    print("\nHTTP proxy response fidelity (relay/universal.py):")

    mock_http_port = alloc_port()
    mock_server = start_mock_http_server(mock_http_port)
    base = f"http://127.0.0.1:{mock_http_port}"

    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000", "PROXY_RATE_LIMIT": "1000"}
    try:
        async with Relay("universal.py", env) as relay:
            expected_big = (b"cowork-tunnel-" * 4096) * 32

            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port, {"url": f"{base}/big", "method": "GET"}
            )
            body = base64.b64decode(result.get("body_b64", ""))
            check("large response is not truncated", body == expected_big,
                  f"got {len(body)} bytes, want {len(expected_big)}")

            # A body larger than the HTTP server's stream limit must still be
            # read in full -- the head is size-capped, the body must not be.
            upload = bytes(range(256)) * 4096  # 1 MiB, deterministic
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"{base}/echo",
                    "method": "POST",
                    "headers": {"Content-Type": "application/octet-stream"},
                    "body_b64": base64.b64encode(upload).decode(),
                },
            )
            echoed = base64.b64decode(result.get("body_b64", ""))
            check("large request body round-trips intact", echoed == upload,
                  f"got {len(echoed)} bytes, want {len(upload)}")

            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port, {"url": f"{base}/redirect", "method": "GET"}
            )
            check("redirect is followed to the final response",
                  result.get("status") == 200, f"got {result.get('status')}")
            check("redirect sets redirected", result.get("redirected") is True,
                  f"got {result.get('redirected')}")
            check("redirect reports final_url",
                  str(result.get("final_url", "")).endswith("/json"),
                  f"got {result.get('final_url')}")

            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port, {"url": f"{base}/cookies", "method": "GET"}
            )
            cookies = result.get("set_cookie") or []
            check("Set-Cookie headers are returned separately", len(cookies) == 2,
                  f"got {cookies}")
            check("Set-Cookie values are not comma-joined",
                  any(c.startswith("b=2;") for c in cookies), f"got {cookies}")
            check("Set-Cookie is kept out of the flat header dict",
                  "Set-Cookie" not in (result.get("headers") or {}),
                  f"headers={result.get('headers')}")

            # Proxy-Authorization and Trailer are hop-by-hop and, unlike
            # Connection, are not re-added by the outbound transport -- their
            # absence at the target is real evidence the relay dropped them.
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"{base}/echo-headers",
                    "method": "GET",
                    "headers": {
                        "X-Test-Header": "forwarded-value",
                        "Proxy-Authorization": "Basic c2hvdWxkLW5vdC1sZWFr",
                        "Trailer": "X-Checksum",
                    },
                },
            )
            echoed = json.loads(base64.b64decode(result.get("body_b64", "")))
            lowered = {k.lower(): v for k, v in echoed.items()}
            check("custom headers reach the target",
                  lowered.get("x-test-header") == "forwarded-value", f"echoed={lowered}")
            check("hop-by-hop Proxy-Authorization is stripped",
                  "proxy-authorization" not in lowered, f"echoed={lowered}")
            check("hop-by-hop Trailer is stripped", "trailer" not in lowered,
                  f"echoed={lowered}")

            # A forwarding proxy must not invent request headers. urllib stamps
            # "Python-urllib/x.y" onto any request without one, which made the
            # relay misrepresent the caller, diverge from the Worker (which adds
            # nothing), and hand targets the exact agent string Cloudflare-
            # fronted sites reject.
            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {"url": f"{base}/echo-headers", "method": "GET"},
            )
            echoed = json.loads(base64.b64decode(result.get("body_b64", "")))
            lowered = {k.lower(): v for k, v in echoed.items()}
            check("relay invents no User-Agent when the envelope has none",
                  "user-agent" not in lowered, f"got {lowered.get('user-agent')!r}")

            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port,
                {
                    "url": f"{base}/echo-headers",
                    "method": "GET",
                    "headers": {"User-Agent": "envelope-agent"},
                },
            )
            echoed = json.loads(base64.b64decode(result.get("body_b64", "")))
            lowered = {k.lower(): v for k, v in echoed.items()}
            check("relay forwards the envelope's User-Agent verbatim",
                  lowered.get("user-agent") == "envelope-agent",
                  f"got {lowered.get('user-agent')!r}")

            result = await asyncio.to_thread(
                _proxy_request, relay.proxy_port, {"url": f"{base}/dupe-headers", "method": "GET"}
            )
            check("duplicate headers are joined with ', '",
                  (result.get("headers") or {}).get("X-Multi") == "one, two",
                  f"got {(result.get('headers') or {}).get('X-Multi')}")

            # An SSH tunnel must still come up on the same port afterwards.
            async with connect(
                relay.url(f"&target=127.0.0.1:{sshd_port}"), open_timeout=5
            ) as ws:
                banner = await asyncio.wait_for(ws.recv(), timeout=5)
                banner = banner if isinstance(banner, bytes) else banner.encode()
                check("SSH works alongside the HTTP proxy",
                      banner.startswith(b"SSH-2.0"), banner.decode().strip())
    finally:
        mock_server.shutdown()


def test_http_proxy_client_unit() -> None:
    """Unit tests for the http_proxy.py client."""
    print("\nHTTP proxy client unit tests:")
    from http_proxy import _build_parser

    # Test the CLI argument parser
    parser = _build_parser()

    args = parser.parse_args(["GET", "https://example.com"])
    check("CLI parser: method", args.method == "GET")
    check("CLI parser: url", args.url == "https://example.com")
    check("CLI parser: no headers", args.headers == [])
    check("CLI parser: no body", args.body is None)
    check("CLI parser: not raw", args.raw is False)

    args = parser.parse_args([
        "POST", "https://api.example.com",
        "-H", "Content-Type: application/json",
        "-H", "Authorization: Bearer tok",
        "-d", '{"key": "val"}',
        "--raw",
    ])
    check("CLI parser: POST method", args.method == "POST")
    check("CLI parser: headers parsed", len(args.headers) == 2)
    check("CLI parser: body parsed", args.body == '{"key": "val"}')
    check("CLI parser: raw flag", args.raw is True)


def test_http_proxy_client_useragent() -> None:
    """The client must not reach a relay as "Python-urllib".

    Cloudflare's edge blocks that agent outright: a Worker-hosted relay answers
    403 (error 1010) before the request ever reaches the Worker, so the default
    urllib agent makes the HTTP proxy unusable on the Cloudflare deployment.
    Verified against the live edge, not inferred.
    """
    print("\nHTTP proxy client User-Agent (client/http_proxy.py):")
    from http_proxy import RELAY_USER_AGENT, relay_fetch

    seen: list[str] = []
    envelopes: list[dict] = []

    class _Recorder(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: ANN001
            pass

        def do_POST(self):
            seen.append(self.headers.get("User-Agent", ""))
            length = int(self.headers.get("Content-Length", 0))
            envelopes.append(json.loads(self.rfile.read(length) or b"{}"))
            body = json.dumps({"status": 200, "headers": {}, "body_b64": ""}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    port = alloc_port()
    server = HTTPServer(("127.0.0.1", port), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for headers in (None, {"User-Agent": "caller-agent"}, {"user-agent": "lowercase-caller"}):
            relay_fetch(
                method="GET",
                url="http://example.invalid/",
                headers=headers,
                relay_url=f"http://127.0.0.1:{port}",
                relay_token=TOKEN,
            )
    finally:
        server.shutdown()

    check("client sends a User-Agent to the relay", bool(seen) and bool(seen[0]),
          f"seen={seen}")
    check("client does not identify as Python-urllib",
          bool(seen) and "python-urllib" not in seen[0].lower(), f"seen={seen}")
    check("client uses the configured agent", bool(seen) and seen[0] == RELAY_USER_AGENT,
          f"seen={seen}, want={RELAY_USER_AGENT}")

    # The agent on the hop to the relay is separate from the one forwarded to
    # the target. GitHub answers 403 to a request carrying neither.
    def env_ua(envelope: dict) -> str | None:
        for key, value in (envelope.get("headers") or {}).items():
            if key.lower() == "user-agent":
                return value
        return None

    check("a default User-Agent is forwarded to the target",
          len(envelopes) == 3 and env_ua(envelopes[0]) == RELAY_USER_AGENT,
          f"got {env_ua(envelopes[0]) if envelopes else None!r}")
    check("a caller-supplied User-Agent wins",
          len(envelopes) > 1 and env_ua(envelopes[1]) == "caller-agent",
          f"got {env_ua(envelopes[1]) if len(envelopes) > 1 else None!r}")
    check("a lowercase caller User-Agent is not overridden",
          len(envelopes) > 2 and env_ua(envelopes[2]) == "lowercase-caller",
          f"got {env_ua(envelopes[2]) if len(envelopes) > 2 else None!r}")


def _python_without_websockets(tmp: str) -> str:
    """Return a python3 that cannot import websockets, on any host.

    The venv branch of bootstrap.sh only runs when the interpreter lacks the
    package. Relying on the host's python3 for that makes the test pass or fail
    depending on whose machine it runs on. A fresh venv without
    --system-site-packages cannot see site-packages, so it is deterministic
    even where websockets is installed system-wide.
    """
    clean = os.path.join(tmp, "clean")
    subprocess.run([sys.executable, "-m", "venv", clean], check=True,
                   capture_output=True, timeout=120)
    return os.path.join(clean, "bin", "python3")


def _stub_wheel(outdir: str, name: str = "websockets", version: str = "99.0") -> None:
    """Write a minimal, valid wheel so pip can install offline.

    Lets the venv-building branch of bootstrap.sh be tested without a package
    index: pip reads PIP_NO_INDEX and PIP_FIND_LINKS from the environment, so
    the real code path runs unmodified against a local file.
    """
    import base64
    import hashlib
    import zipfile

    os.makedirs(outdir, exist_ok=True)
    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": f'__version__ = "{version}"\n',
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        f"{dist}/WHEEL": ("Wheel-Version: 1.0\nGenerator: test\n"
                          "Root-Is-Purelib: true\nTag: py3-none-any\n"),
    }
    record = []
    with zipfile.ZipFile(os.path.join(outdir, f"{name}-{version}-py3-none-any.whl"), "w") as z:
        for path, content in files.items():
            z.writestr(path, content)
            digest = base64.urlsafe_b64encode(
                hashlib.sha256(content.encode()).digest()).rstrip(b"=").decode()
            record.append(f"{path},sha256={digest},{len(content)}")
        record.append(f"{dist}/RECORD,,")
        z.writestr(f"{dist}/RECORD", "\n".join(record) + "\n")


def test_bootstrap() -> None:
    """Exercise bootstrap.sh offline, against a local copy of the repo.

    The installer had no automated coverage until now, because it fetches from
    GitHub and this suite runs offline. Two bugs reached a tagged release
    through that gap: a successful run exited 1, and an unusable
    COWORK_TUNNEL_PYTHON was written into the SSH config regardless. Both are
    asserted below.

    COWORK_TUNNEL_REPO_RAW points at a local server, and PATH supplies a
    python3 that already imports websockets, so nothing is downloaded from the
    internet and no package is installed. The venv-building branch needs a real
    package index and is therefore verified by hand, not here.
    """
    print("\nBootstrap installer (client/bootstrap.sh):")

    script = os.path.join(REPO, "client", "bootstrap.sh")
    handler_mode = {"mode": "ok"}

    class _Serve(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: ANN001
            pass

        def do_GET(self):
            name = os.path.basename(self.path)
            if handler_mode["mode"] == "404":
                self.send_error(404)
                return
            if handler_mode["mode"] == "corrupt":
                body = b"<html>not a python script</html>"
            else:
                with open(os.path.join(CLIENT_DIR, name), "rb") as fh:
                    body = fh.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    port = alloc_port()
    server = HTTPServer(("127.0.0.1", port), _Serve)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def run(tmp: str, extra: dict[str, str] | None = None,
            interpreter: str | None = None) -> subprocess.CompletedProcess:
        # A python3 on PATH that can import websockets, so bootstrap takes the
        # "already installed" branch and never reaches for the network.
        shim = os.path.join(tmp, "bin")
        os.makedirs(shim, exist_ok=True)
        link = os.path.join(shim, "python3")
        if not os.path.exists(link):
            # A wrapper, not a symlink: a venv interpreter locates pyvenv.cfg
            # relative to the path it was invoked through, so a symlink parked
            # in a temp directory silently demotes it to the system Python.
            with open(link, "w") as fh:
                fh.write(f'#!/bin/sh\nexec "{interpreter or sys.executable}" "$@"\n')
            os.chmod(link, 0o755)
        env = {
            **os.environ,
            "HOME": tmp,
            "PATH": shim + os.pathsep + os.environ["PATH"],
            "COWORK_TUNNEL_DIR": os.path.join(tmp, "ct"),
            "COWORK_TUNNEL_REPO_RAW": f"http://127.0.0.1:{port}",
            "COWORK_RELAY_URL": "wss://relay.example.com/ssh",
            "COWORK_RELAY_TOKEN": "test-token",
        }
        env.update(extra or {})
        return subprocess.run(["bash", script], env=env, capture_output=True,
                              text=True, timeout=120)

    def proxy_command(tmp: str) -> str:
        cfg = os.path.join(tmp, ".ssh", "config")
        if not os.path.exists(cfg):
            return ""
        for line in open(cfg):
            if "ProxyCommand" in line:
                return line.split("ProxyCommand", 1)[1].strip()
        return ""

    try:
        # Happy path. The exit status is the point: an EXIT trap whose last
        # command is falsy silently turns success into failure.
        with tempfile.TemporaryDirectory() as tmp:
            r = run(tmp)
            check("bootstrap exits 0 on success", r.returncode == 0,
                  f"rc={r.returncode} err={r.stderr[-160:]}")
            ct = os.path.join(tmp, "ct")
            for name in ("ws_proxy.py", "http_proxy.py"):
                path = os.path.join(ct, name)
                check(f"bootstrap installs {name}", os.path.exists(path))
                check(f"{name} is executable",
                      os.path.exists(path) and os.access(path, os.X_OK))
            cmd = proxy_command(tmp)
            check("ProxyCommand names an absolute ws_proxy.py",
                  "/ws_proxy.py" in cmd and cmd.split()[-1].startswith("/"), cmd)
            check("no venv built when the interpreter already has websockets",
                  not os.path.isdir(os.path.join(ct, "venv")))

            r = run(tmp)
            check("re-running exits 0", r.returncode == 0, f"rc={r.returncode}")
            cfg = open(os.path.join(tmp, ".ssh", "config")).read()
            check("re-running leaves exactly one Host * block",
                  cfg.count("cowork-tunnel begin") == 1,
                  f"blocks={cfg.count('cowork-tunnel begin')}")

        # A caller-supplied interpreter is used as-is and never installed into.
        with tempfile.TemporaryDirectory() as tmp:
            r = run(tmp, {"COWORK_TUNNEL_PYTHON": sys.executable})
            check("supplied interpreter is honoured", r.returncode == 0
                  and proxy_command(tmp).startswith(sys.executable), proxy_command(tmp))
            check("supplied interpreter suppresses the venv",
                  not os.path.isdir(os.path.join(tmp, "ct", "venv")))

        # ssh runs ProxyCommand from an arbitrary directory, so a relative path
        # has to be resolved before it is written.
        with tempfile.TemporaryDirectory() as tmp:
            rel = os.path.relpath(sys.executable, os.getcwd())
            r = run(tmp, {"COWORK_TUNNEL_PYTHON": rel})
            check("a relative interpreter is resolved to an absolute path",
                  r.returncode == 0 and proxy_command(tmp).startswith("/"),
                  proxy_command(tmp))

        # An unusable interpreter must stop the run rather than write a Host *
        # block that breaks every SSH connection on the machine.
        with tempfile.TemporaryDirectory() as tmp:
            r = run(tmp, {"COWORK_TUNNEL_PYTHON": "/nonexistent/python3"})
            check("an unusable interpreter is fatal", r.returncode != 0,
                  f"rc={r.returncode}")
            check("nothing is written to the SSH config when it fails",
                  proxy_command(tmp) == "", proxy_command(tmp))

        # The venv branch, which is what runs on a host whose python3 lacks
        # websockets. No shim here: the system interpreter genuinely cannot
        # import it, so bootstrap must build a venv. pip is pointed at a local
        # wheel, so this stays offline while exercising the real code path.
        with tempfile.TemporaryDirectory() as tmp:
            wheels = os.path.join(tmp, "wheels")
            _stub_wheel(wheels)
            r = run(tmp, {"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": wheels},
                    interpreter=_python_without_websockets(tmp))
            venv = os.path.join(tmp, "ct", "venv")
            built = os.path.isdir(venv)
            check("bootstrap builds a venv when websockets is missing", built,
                  f"rc={r.returncode} err={r.stderr[-200:]}")
            check("the venv branch exits 0", r.returncode == 0, f"rc={r.returncode}")
            check("ProxyCommand points into the venv it built",
                  proxy_command(tmp).startswith(os.path.join(venv, "bin")),
                  proxy_command(tmp))
            # Guarded: running a binary that was never created raises
            # FileNotFoundError, which would abort the whole suite rather than
            # failing one check.
            if built:
                got = subprocess.run([os.path.join(venv, "bin", "python3"),
                                      "-c", "import websockets; print('ok')"],
                                     capture_output=True, text=True)
                ok, detail = got.stdout.strip() == "ok", got.stderr[-120:]
            else:
                ok, detail = False, "no venv was built"
            check("the venv it built can import websockets", ok, detail)

        # Same branch, but nothing installable. The SSH half cannot work, yet
        # http_proxy.py needs no third-party package, so the run must degrade
        # rather than abort.
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, "empty")
            os.makedirs(empty, exist_ok=True)
            r = run(tmp, {"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": empty},
                    interpreter=_python_without_websockets(tmp))
            check("an uninstallable dependency is not fatal", r.returncode == 0,
                  f"rc={r.returncode}")
            check("it says what is wrong", "could not install websockets" in r.stderr.lower(),
                  r.stderr[-160:])
            check("the HTTP proxy is installed anyway",
                  os.path.exists(os.path.join(tmp, "ct", "http_proxy.py")))

        # A download that 404s must not be installed as if it were a script.
        with tempfile.TemporaryDirectory() as tmp:
            handler_mode["mode"] = "404"
            r = run(tmp)
            check("a failed download is fatal", r.returncode != 0, f"rc={r.returncode}")
            check("a failed download installs nothing",
                  not os.path.exists(os.path.join(tmp, "ct", "ws_proxy.py")))

        # An error page served with 200 must be rejected on its shebang.
        with tempfile.TemporaryDirectory() as tmp:
            handler_mode["mode"] = "corrupt"
            r = run(tmp)
            check("a non-script payload is refused", r.returncode != 0, f"rc={r.returncode}")
            check("a non-script payload is not installed",
                  not os.path.exists(os.path.join(tmp, "ct", "ws_proxy.py")))
    finally:
        handler_mode["mode"] = "ok"
        server.shutdown()


async def test_http_proxy_client_integration(sshd_port: int) -> None:
    """Integration test: use http_proxy.py as a subprocess through the relay."""
    print("\nHTTP proxy client integration (client/http_proxy.py):")

    mock_http_port = alloc_port()
    mock_server = start_mock_http_server(mock_http_port)

    env = {"WS_PORT": str(alloc_port()), "RATE_LIMIT": "1000"}
    try:
        async with Relay("universal.py", env) as relay:
            http_proxy_script = os.path.join(REPO, "client", "http_proxy.py")

            # Test the client as a subprocess with --raw
            proc = await asyncio.create_subprocess_exec(
                sys.executable, http_proxy_script,
                "GET", f"http://127.0.0.1:{mock_http_port}/json",
                "--raw",
                env={
                    **os.environ,
                    "COWORK_RELAY_URL": f"http://127.0.0.1:{relay.proxy_port}",
                    "COWORK_RELAY_TOKEN": TOKEN,
                },
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
                parsed = json.loads(out)
                check("http_proxy.py CLI GET works",
                      parsed.get("greeting") == "hello",
                      f"out={out[:100]}, err={err.decode()[:200]}")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                check("http_proxy.py CLI GET works", False, "timeout")
            except Exception as e:
                check("http_proxy.py CLI GET works", False,
                      f"{type(e).__name__}: {e}")
    finally:
        mock_server.shutdown()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
async def _guard(fn, *args) -> None:
    """Run one test function, converting a crash into a single failed check.

    Without this, an unexpected exception aborts the whole run: a
    FileNotFoundError in one test once took roughly a hundred later checks with
    it, and the summary line never printed, so the run looked truncated rather
    than failed.
    """
    try:
        result = fn(*args)
        if inspect.isawaitable(result):
            await result
    except Exception as e:  # noqa: BLE001 - one broken test must not hide the rest
        check(f"{fn.__name__} ran without raising", False,
              f"{type(e).__name__}: {e}")


async def run() -> bool:
    print("=== cowork-tunnel test suite ===")

    await _guard(test_target_parsing)
    await _guard(test_private_detection)
    await _guard(test_token_comparison)
    await _guard(test_allowlist_matching)
    await _guard(test_env_parsing)

    sshd_port, hangup_port = alloc_port(), alloc_port()
    echo_srv = await asyncio.start_server(sshd_echo, "127.0.0.1", sshd_port)
    hang_srv = await asyncio.start_server(sshd_hangup, "127.0.0.1", hangup_port)

    try:
        await _guard(test_standalone, sshd_port, hangup_port)
        await _guard(test_limits, sshd_port)
        await _guard(test_universal, sshd_port)
        await _guard(test_ws_proxy_client, sshd_port)

        # HTTP proxy tests
        await _guard(test_http_proxy_url_normalization)
        await _guard(test_http_proxy_header_stripping)
        await _guard(test_http_proxy_client_unit)
        await _guard(test_http_proxy_client_useragent)
        await _guard(test_bootstrap)
        await _guard(test_http_proxy, sshd_port)
        await _guard(test_http_proxy_hardening, sshd_port)
        await _guard(test_no_permessage_deflate, sshd_port)
        await _guard(test_upstream_tls_verification)
        await _guard(test_http_proxy_fidelity, sshd_port)
        await _guard(test_http_proxy_client_integration, sshd_port)
    finally:
        echo_srv.close()
        hang_srv.close()
        await echo_srv.wait_closed()
        await hang_srv.wait_closed()

    total = len(_passed) + len(_failed)
    print(f"\n{len(_passed)}/{total} checks passed", end="")
    if _failed:
        print(f", {len(_failed)} FAILED:")
        for name, detail in _failed:
            print(f"  - {name}" + (f" ({detail})" if detail else ""))
        return False
    print(" -- ALL PASS")
    return True


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
