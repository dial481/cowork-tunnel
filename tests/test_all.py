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
import importlib.util
import os
import sys
import types
from urllib.parse import quote

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELAY_DIR = os.path.join(REPO, "relay")
CLIENT = os.path.join(REPO, "client", "ws_proxy.py")

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
        self.env = env
        self.port = int(env["WS_PORT"])
        self.proc = None

    async def __aenter__(self):
        env = {**os.environ, "RELAY_TOKEN": TOKEN, **self.env}
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable,
            os.path.join(RELAY_DIR, self.script),
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        for _ in range(60):
            await asyncio.sleep(0.1)
            if self.proc.returncode is not None:
                err = (await self.proc.stderr.read()).decode()
                raise RuntimeError(f"{self.script} exited rc={self.proc.returncode}: {err}")
            try:
                _r, w = await asyncio.open_connection("127.0.0.1", self.port)
                w.close()
                return self
            except OSError:
                continue
        raise RuntimeError(f"{self.script} never bound port {self.port}")

    async def __aexit__(self, *_exc):
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()

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


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
async def run() -> bool:
    print("=== cowork-tunnel test suite ===")

    test_target_parsing()
    test_private_detection()
    test_token_comparison()
    test_allowlist_matching()

    sshd_port, hangup_port = alloc_port(), alloc_port()
    echo_srv = await asyncio.start_server(sshd_echo, "127.0.0.1", sshd_port)
    hang_srv = await asyncio.start_server(sshd_hangup, "127.0.0.1", hangup_port)

    try:
        await test_standalone(sshd_port, hangup_port)
        await test_limits(sshd_port)
        await test_universal(sshd_port)
        await test_ws_proxy_client(sshd_port)
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
