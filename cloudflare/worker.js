/**
 * Cowork SSH Tunnel - Cloudflare Worker
 *
 * Bridges WebSocket connections to TCP (SSH) endpoints.
 * Zero server installation required. Deploy once, reach any server.
 *
 * Architecture:
 *   Cowork sandbox -> WSS/443 -> CF Edge -> Worker -> TCP:22 -> Any server
 *
 * Usage:
 *   wss://tunnel.you.workers.dev/?target=192.168.1.1:22&token=xxx
 *
 * By default this worker will connect to ANY target host and port. The bearer
 * token is the access control. Treat it like an SSH private key: anyone who
 * has it can open TCP connections from your Cloudflare account. Rotate it with
 * `wrangler secret put RELAY_TOKEN` if it is ever exposed.
 *
 * Environment variables (set in wrangler.toml or via `wrangler secret put`):
 *   RELAY_TOKEN    - Required. Bearer token for authentication.
 *   ALLOWED_HOSTS  - Optional. Comma-separated allowed target hosts/IPs.
 *                    Empty (default) = any target allowed.
 *   BLOCK_PRIVATE  - Optional. "1"/"true" refuses targets that look private.
 *                    Default off. ALLOWED_HOSTS entries override it.
 *   DEFAULT_PORT   - Optional. Default port if not in target (default: 22).
 */

import { connect } from "cloudflare:sockets";

// WebSocket close reasons are capped at 123 UTF-8 bytes by the protocol.
const MAX_CLOSE_REASON = 100;
// Cap on bytes queued toward the target before we give up, so a slow or stuck
// peer cannot grow the isolate's memory until it is killed with no diagnostic.
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({ status: "ok", mode: "cloudflare-worker" }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Require WebSocket upgrade
    const upgrade = request.headers.get("Upgrade");
    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }

    if (!env.RELAY_TOKEN) {
      return new Response("Server misconfigured: RELAY_TOKEN not set", {
        status: 500,
      });
    }

    // Auth: token from query string or Authorization header
    const token =
      url.searchParams.get("token") ||
      (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");

    if (!(await tokensMatch(token, env.RELAY_TOKEN))) {
      return new Response("Forbidden", { status: 403 });
    }

    // Parse target
    const rawTarget = url.searchParams.get("target");
    if (!rawTarget) {
      return new Response("Missing target parameter", { status: 400 });
    }

    const defaultPort = parseInt(env.DEFAULT_PORT || "22", 10);
    const parsed = parseTarget(
      rawTarget,
      Number.isInteger(defaultPort) ? defaultPort : 22
    );
    if (!parsed) {
      return new Response("Invalid target", { status: 400 });
    }
    const [targetHost, targetPort] = parsed;

    // Optional allowlist. An explicit entry is a deliberate decision, so it
    // also exempts the target from the private-address guard below --
    // otherwise allowlisting an internal host could never work.
    const allowlisted = isAllowlisted(targetHost, env.ALLOWED_HOSTS);
    if (env.ALLOWED_HOSTS && !allowlisted) {
      return new Response("Target not in allowlist", { status: 403 });
    }

    // Optional private-address guard, off by default.
    const blockPrivate = /^(1|true|yes|on)$/i.test(env.BLOCK_PRIVATE || "");
    if (blockPrivate && !allowlisted && isPrivateOrLoopback(targetHost)) {
      return new Response("Private/loopback addresses not allowed", {
        status: 403,
      });
    }

    // Create the WebSocket pair and accept before any await, so no inbound
    // message can be dropped between accept() and listener registration.
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    bridge(server, targetHost, targetPort);

    return new Response(null, { status: 101, webSocket: client });
  },
};

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/**
 * Wire a WebSocket to a TCP socket. Never throws; all failures are reported to
 * the client as a close frame.
 */
function bridge(server, targetHost, targetPort) {
  const target = `${targetHost}:${targetPort}`;
  let tcp;
  try {
    tcp = connect({ hostname: targetHost, port: targetPort });
  } catch (e) {
    safeClose(server, 1011, `Cannot connect to ${target}: ${e.message}`);
    return;
  }

  let closed = false;
  let writer = null;
  let buffered = 0;
  const pending = []; // frames that arrive before the socket finishes opening

  const teardown = (code, reason) => {
    if (closed) return;
    closed = true;
    safeClose(server, code, reason);
    closeSocket(tcp);
  };

  const write = (chunk) => {
    // write() enqueues synchronously, so call order fixes stream order even
    // though the returned promise settles later.
    writer.write(chunk).then(
      () => {
        buffered -= chunk.byteLength;
      },
      () => teardown(1011, "Target write failed")
    );
  };

  // Registered synchronously, before any await. An SSH client sends its
  // version string the instant the tunnel opens, without waiting for the
  // server -- if that frame arrives while the TCP socket is still connecting
  // and nothing is listening yet, it is lost and the handshake never completes.
  server.addEventListener("message", (event) => {
    if (closed) return;
    if (typeof event.data === "string") {
      // This is a byte tunnel. Silently encoding a text frame would inject
      // corrupt bytes mid-stream and surface as an SSH MAC error.
      teardown(1003, "Binary frames only");
      return;
    }
    const chunk = new Uint8Array(event.data);
    buffered += chunk.byteLength;
    if (buffered > MAX_BUFFERED_BYTES) {
      teardown(1009, "Target not draining; buffer limit exceeded");
      return;
    }
    if (writer) write(chunk);
    else pending.push(chunk);
  });

  server.addEventListener("close", () => teardown(1000, "Client closed"));
  server.addEventListener("error", () => teardown(1011, "Client error"));

  // connect() is synchronous and does no network work: DNS failure, refusal
  // and timeout all surface as a rejection of `opened`. Without handling it
  // the rejection is unhandled and the client sees a normal 1000 close,
  // indistinguishable from a session the user ended themselves.
  tcp.opened.then(
    () => {
      if (closed) {
        closeSocket(tcp);
        return;
      }
      writer = tcp.writable.getWriter();
      // Flush synchronously so queued frames stay ahead of any later arrival.
      for (const chunk of pending.splice(0)) write(chunk);
      readLoop();
    },
    (e) => teardown(1011, `Cannot connect to ${target}: ${e.message}`)
  );

  async function readLoop() {
    const reader = tcp.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (closed) break;
        server.send(value);
      }
      teardown(1000, "Target closed connection");
    } catch (e) {
      teardown(1011, `Target read failed: ${e.message}`);
    } finally {
      try {
        reader.releaseLock();
      } catch {}
    }
  }
}

function safeClose(ws, code, reason) {
  try {
    ws.close(code, truncate(reason));
  } catch {}
}

function closeSocket(tcp) {
  try {
    // close() tears down both directions; a reader parked in read() is
    // unblocked by this, which a `done` flag alone can never do.
    tcp.close();
  } catch {}
}

function truncate(reason) {
  const text = String(reason || "");
  return text.length > MAX_CLOSE_REASON
    ? text.slice(0, MAX_CLOSE_REASON - 1) + "…"
    : text;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/**
 * Compare tokens in constant time. Both sides are hashed first so the
 * comparison operates on equal-length buffers regardless of input length.
 */
async function tokensMatch(supplied, expected) {
  if (!supplied) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(supplied)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/;

/**
 * Parse "host", "host:port", "[v6]" or "[v6]:port" into [host, port].
 * Returns null if malformed or the port is out of range.
 */
function parseTarget(raw, defaultPort) {
  const value = (raw || "").trim();
  if (!value) return null;

  let host;
  let port = defaultPort;

  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end === -1) return null;
    host = value.slice(1, end);
    const rest = value.slice(end + 1);
    if (rest) {
      if (!/^:\d+$/.test(rest)) return null;
      port = parseInt(rest.slice(1), 10);
    }
    if (!looksLikeIPv6(host)) return null;
  } else if ((value.match(/:/g) || []).length > 1) {
    // Bare IPv6 literal; a port would be ambiguous without brackets.
    if (!looksLikeIPv6(value)) return null;
    host = value;
  } else if (value.includes(":")) {
    const idx = value.lastIndexOf(":");
    host = value.slice(0, idx);
    const portStr = value.slice(idx + 1);
    if (!/^\d+$/.test(portStr)) return null;
    port = parseInt(portStr, 10);
  } else {
    host = value;
  }

  if (!host) return null;
  if (!looksLikeIPv6(host) && !HOSTNAME_RE.test(host)) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return [host, port];
}

function looksLikeIPv6(value) {
  return value.includes(":") && /^[0-9A-Fa-f:.]+$/.test(value);
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

function isAllowlisted(host, allowedHosts) {
  if (!allowedHosts) return false;
  const needle = host.toLowerCase();
  return allowedHosts
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
    .includes(needle);
}

/**
 * Best-effort check on a literal target string.
 *
 * This is lexical only -- it never resolves DNS, so a hostname pointing at a
 * private address is not caught. On Cloudflare that gap is largely academic
 * (a Worker's egress cannot reach your LAN, and there is no instance metadata
 * service at 169.254.169.254), and Workers has no resolver API to close it
 * with. Defense in depth, not a security boundary.
 */
function isPrivateOrLoopback(host) {
  const value = host.toLowerCase();

  if (
    value === "localhost" ||
    value === "localhost.localdomain" ||
    value.endsWith(".local") ||
    value.endsWith(".internal")
  ) {
    return true;
  }

  if (value.includes(":")) {
    const stripped = value.replace(/^\[|\]$/g, "");
    if (stripped === "::1" || stripped === "::") return true;
    if (stripped.startsWith("fe80:")) return true; // link-local
    if (/^f[cd]/.test(stripped)) return true; // unique local
    const v4mapped = stripped.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (v4mapped) return isPrivateIPv4(v4mapped[1]);
    return false;
  }

  return isPrivateIPv4(value);
}

function isPrivateIPv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) {
    return false;
  }
  const [a, b] = parts.map((p) => parseInt(p, 10));
  if (parts.some((p) => parseInt(p, 10) > 255)) return false;

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 + TEST-NET-1
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && b >= 18 && b <= 19) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}
