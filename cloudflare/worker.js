/**
 * Cowork Tunnel - Cloudflare Worker
 *
 * Two modes on one deployment:
 *   1. WebSocket upgrade -> SSH tunneling (existing)
 *   2. POST /proxy       -> HTTP request forwarding (new)
 *
 * Architecture:
 *   SSH:  Cowork sandbox -> WSS/443 -> CF Edge -> Worker -> TCP:22 -> Any server
 *   HTTP: Cowork sandbox -> POST /proxy -> CF Edge -> Worker -> fetch() -> Any URL
 *
 * Usage:
 *   SSH:  wss://tunnel.you.workers.dev/?target=192.168.1.1:22&token=xxx
 *   HTTP: POST https://tunnel.you.workers.dev/proxy (with JSON envelope)
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
 *   MAX_RESPONSE_BODY - Optional. Largest upstream response the HTTP proxy will
 *                    return, in bytes (default: 33554432, i.e. 32 MiB). Beyond
 *                    this the caller gets a 502 rather than the isolate dying
 *                    of memory exhaustion mid-encode.
 */

import { connect } from "cloudflare:sockets";

// WebSocket close reasons are capped at 123 UTF-8 bytes by the protocol.
const MAX_CLOSE_REASON = 100;
// Cap on bytes queued toward the target before we give up, so a slow or stuck
// peer cannot grow the isolate's memory until it is killed with no diagnostic.
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;
// Maximum request body for POST /proxy (8 MiB).
const MAX_PROXY_BODY = 8 * 1024 * 1024;

// Maximum upstream response body, matching the Python relay's default.
//
// The response exists three times over during encoding -- the ArrayBuffer, the
// binary string, and the base64 output -- so an uncapped forward of a large
// download (a release asset, a git pack, a bulk API response) walks the isolate
// into its 128 MB memory limit and dies with no diagnostic the caller can see.
// A refusal the caller can read is strictly better than a silent crash.
// Override with a MAX_RESPONSE_BODY var in wrangler.toml.
const DEFAULT_MAX_RESPONSE_BODY = 32 * 1024 * 1024;

function maxResponseBody(env) {
  const raw = parseInt(env.MAX_RESPONSE_BODY || "", 10);
  return Number.isInteger(raw) && raw > 0 ? raw : DEFAULT_MAX_RESPONSE_BODY;
}

// Schemes the HTTP proxy will forward.
const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

// RFC 9110 token, used to validate method names.
const HTTP_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// Hop-by-hop headers that must not be forwarded.
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          mode: "cloudflare-worker",
          capabilities: ["ssh", "proxy"],
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // POST /proxy -- HTTP request forwarding
    if (url.pathname === "/proxy") {
      if (request.method !== "POST") {
        return jsonError(405, "Method not allowed");
      }
      return handleProxy(request, url, env);
    }

    // Require WebSocket upgrade for all other paths
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
    const blockedReason = blockPrivate && !allowlisted ? blockedTargetReason(targetHost) : null;
    if (blockedReason) {
      return new Response(blockedReason, { status: 403 });
    }

    // Create the WebSocket pair and accept before any await, so no inbound
    // message can be dropped between accept() and listener registration.
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    // Recent compatibility dates follow the WebSocket spec and deliver binary
    // frames as Blob by default. The bridge reads them synchronously as
    // ArrayBuffer (an async Blob read could reorder frames), and
    // `new Uint8Array(blob)` is silently empty, which loses every byte the
    // client sends. Ask for ArrayBuffer explicitly so the bridge keeps
    // working when compatibility_date is bumped.
    server.binaryType = "arraybuffer";

    bridge(server, targetHost, targetPort);

    return new Response(null, { status: 101, webSocket: client });
  },
};

// ---------------------------------------------------------------------------
// HTTP Proxy
// ---------------------------------------------------------------------------

function jsonError(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Log one proxied request, mirroring the Python relay's format.
 *
 * Host only, never the full URL: a forwarded URL can carry tokens in its query
 * string, and Workers logs are not the place for them.
 */
function logProxy(method, host, outcome) {
  console.log(`[proxy] ${method} ${host} -> ${outcome}`);
}

/**
 * Flatten response headers, keeping Set-Cookie out of the flat object.
 *
 * headers.entries() folds repeated fields into one comma-joined value. That is
 * correct for ordinary headers and wrong for Set-Cookie, where a comma is legal
 * inside a cookie's Expires date -- joining them produces cookies no client can
 * parse. They are returned separately so the caller gets them verbatim.
 *
 * @returns {{headers: Object, cookies: string[]}}
 */
function flattenResponseHeaders(headers) {
  const out = {};
  for (const [key, value] of headers.entries()) {
    const lower = key.toLowerCase();
    if (lower === "set-cookie" || HOP_BY_HOP.has(lower)) continue;
    out[key] = value;
  }
  const cookies =
    typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  return { headers: out, cookies };
}

/**
 * Handle POST /proxy -- forward an HTTP request described by a JSON envelope.
 */
async function handleProxy(request, url, env) {
  if (!env.RELAY_TOKEN) {
    return jsonError(500, "Server misconfigured");
  }

  // Auth: same as the SSH path.
  const token =
    url.searchParams.get("token") ||
    (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");

  if (!(await tokensMatch(token, env.RELAY_TOKEN))) {
    logProxy("-", request.headers.get("CF-Connecting-IP") || "?", "401 auth failed");
    return jsonError(401, "Forbidden");
  }

  // Size guard before reading the body.
  const cl = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (cl > MAX_PROXY_BODY) {
    return jsonError(413, "Request body too large");
  }

  let envelope;
  try {
    const raw = await request.text();
    if (new Blob([raw]).size > MAX_PROXY_BODY) {
      return jsonError(413, "Request body too large");
    }
    envelope = JSON.parse(raw);
  } catch {
    return jsonError(400, "Bad request: invalid JSON");
  }

  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return jsonError(400, "Bad request: envelope must be a JSON object");
  }
  if (!envelope.url || typeof envelope.url !== "string") {
    return jsonError(400, "Bad request: missing or invalid 'url'");
  }
  if (!envelope.method || typeof envelope.method !== "string") {
    return jsonError(400, "Bad request: missing or invalid 'method'");
  }

  const method = envelope.method.toUpperCase();
  if (!HTTP_TOKEN_RE.test(method)) {
    return jsonError(400, "Bad request: invalid 'method'");
  }

  // Only http(s) is forwarded. The Workers runtime rejects other schemes
  // anyway, but refusing here keeps the error a documented 400 rather than an
  // opaque 502, and keeps parity with the Python relay.
  let parsedTarget;
  try {
    parsedTarget = new URL(envelope.url);
  } catch {
    return jsonError(400, "Bad request: invalid 'url'");
  }
  if (!ALLOWED_SCHEMES.has(parsedTarget.protocol)) {
    return jsonError(
      400,
      `Bad request: unsupported URL scheme: ${parsedTarget.protocol.replace(":", "")}`
    );
  }

  // Build the outgoing request. Headers.set() throws on a malformed name or
  // value; that is a caller error, so report it as 400 rather than a 500.
  const outHeaders = new Headers();
  if (envelope.headers && typeof envelope.headers === "object") {
    try {
      for (const [k, v] of Object.entries(envelope.headers)) {
        if (!HOP_BY_HOP.has(k.toLowerCase())) {
          outHeaders.set(k, String(v));
        }
      }
    } catch (e) {
      return jsonError(400, `Bad request: invalid header: ${e.message}`);
    }
  }

  let outBody = null;
  if (envelope.body_b64) {
    if (typeof envelope.body_b64 !== "string") {
      return jsonError(400, "Bad request: invalid 'body_b64'");
    }
    try {
      // Binary body takes precedence.
      outBody = Uint8Array.from(atob(envelope.body_b64), (c) => c.charCodeAt(0));
    } catch {
      return jsonError(400, "Bad request: invalid 'body_b64': not valid base64");
    }
  } else if (envelope.body != null) {
    if (typeof envelope.body !== "string") {
      return jsonError(400, "Bad request: invalid 'body': expected a string");
    }
    outBody = envelope.body;
  }

  // Methods that must not have a body per HTTP spec.
  const noBodyMethods = ["GET", "HEAD"];

  let upstream;
  try {
    upstream = await fetch(envelope.url, {
      method,
      headers: outHeaders,
      body: noBodyMethods.includes(method) ? undefined : outBody,
      redirect: "follow",
    });
  } catch (e) {
    logProxy(method, parsedTarget.host, `502 ${e.message}`);
    return jsonError(502, `Upstream error: ${e.message}`);
  }

  const bodyLimit = maxResponseBody(env);

  // Refuse before buffering when the target declares an oversized body. This is
  // advisory -- Content-Length may be absent or wrong -- so the real check runs
  // again on the bytes actually received.
  const declared = parseInt(upstream.headers.get("Content-Length") || "", 10);
  if (Number.isInteger(declared) && declared > bodyLimit) {
    logProxy(method, parsedTarget.host, `502 response too large (${declared} bytes)`);
    return jsonError(502, `Upstream response exceeds ${bodyLimit} bytes`);
  }

  // The body streams in after the response head, so a connection that dies
  // mid-transfer fails here rather than at fetch().
  let respBody;
  try {
    respBody = await upstream.arrayBuffer();
  } catch (e) {
    logProxy(method, parsedTarget.host, `502 ${e.message}`);
    return jsonError(502, `Upstream error reading body: ${e.message}`);
  }
  const bodyBytes = new Uint8Array(respBody);

  // Checked before encoding, which is where the memory actually triples.
  if (bodyBytes.length > bodyLimit) {
    logProxy(method, parsedTarget.host, `502 response too large (${bodyBytes.length} bytes)`);
    return jsonError(502, `Upstream response exceeds ${bodyLimit} bytes`);
  }

  // Chunked conversion avoids "Maximum call stack size exceeded" when the
  // spread operator is used on large arrays (V8 limit is ~125 K arguments).
  let bodyBin = "";
  for (let i = 0; i < bodyBytes.length; i += 8192) {
    bodyBin += String.fromCharCode.apply(
      null,
      bodyBytes.subarray(i, Math.min(i + 8192, bodyBytes.length))
    );
  }
  const bodyB64 = btoa(bodyBin);

  const { headers: respHeaders, cookies } = flattenResponseHeaders(upstream.headers);
  const result = {
    status: upstream.status,
    headers: respHeaders,
    body_b64: bodyB64,
  };
  if (cookies.length) {
    result.set_cookie = cookies;
  }

  if (upstream.redirected) {
    result.redirected = true;
    result.final_url = upstream.url;
  }

  logProxy(method, parsedTarget.host, String(upstream.status));

  return new Response(JSON.stringify(result), {
    headers: { "Content-Type": "application/json" },
  });
}

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

  // Target -> client has no backpressure here: a Workers WebSocket has no
  // bufferedAmount and send() never waits, so frames the client has not
  // taken yet queue in the Worker (measured in workerd: 400 MB sent to a
  // stalled reader raised memory by about 430 MB). For ssh, scp, sftp and
  // rsync that queue stays small, because the target only sends as much as
  // the client's SSH channel window allows (measured: a 300 MB scp download
  // throttled to 5 MB/s used no more memory than an unthrottled one). A
  // protocol without its own flow control, tunnelled to a slow client, can
  // grow it without limit; fixing that needs acknowledgements from the
  // client, which the existing clients do not send.
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
 *
 * The target is put into canonical form first (WHATWG URL host parsing), so
 * other spellings of the same address are caught too: 127.1, 2130706433,
 * 0x7f000001 and 0177.0.0.1 all become 127.0.0.1, and IPv6 literals are
 * compressed, e.g. [0:0:0:0:0:0:0:1] becomes [::1].
 */
function isPrivateOrLoopback(host) {
  return blockedTargetReason(host) !== null;
}

/**
 * Why BLOCK_PRIVATE refuses this target, or null if it does not. The reason
 * is sent back to the client, so it says what to change.
 */
function blockedTargetReason(host) {
  const typed = String(host).toLowerCase().replace(/^\[|\]$/g, "");
  const value = canonicalHost(host);
  const PRIVATE = "Private/loopback addresses not allowed";

  if (
    value === "localhost" ||
    value === "localhost.localdomain" ||
    value.endsWith(".localhost") ||
    value.endsWith(".local") ||
    value.endsWith(".internal")
  ) {
    return PRIVATE;
  }

  // An IP literal written in a non-standard way (127.1, 0x7f000001, leading
  // zeros, a trailing dot, an IPv6 form the parser rejects) is refused
  // outright. Different parsers disagree on what such strings mean -- 0127.0.0.1
  // is 87.0.0.1 to a URL parser but may be 127.0.0.1 to another -- so the only
  // safe answer is not to guess, and not to suggest an IPv4 rewrite either.
  const ipLike = typed.includes(":") || /^[0-9a-fx.]+$/.test(typed);
  if (ipLike && value !== typed && value !== `[${typed}]`) {
    if (!value.startsWith("[")) {
      return typed.includes(":")
        ? "Target address is not a valid IPv6 address"
        : "Target address is not in standard form; write IPv4 as four decimal numbers without leading zeros";
    }
    // An IPv4-mapped address (::ffff:8.8.8.8) is better written as the plain
    // IPv4 address than as the hex form the URL parser prints.
    const g = ipv6Groups(value.slice(1, -1));
    if (g && g.slice(0, 5).every((n) => n === 0) && g[5] === 0xffff) {
      return `Target address is not in standard form; write it as ${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    }
    return `Target address is not in standard form; write it as ${value}`;
  }

  if (value.startsWith("[")) {
    const g = ipv6Groups(value.slice(1, -1));
    if (!g) return "Target address is not in standard form";
    const zero = (from, to) => g.slice(from, to).every((n) => n === 0);
    if (zero(0, 7) && g[7] <= 1) return PRIVATE; // :: and ::1
    if ((g[0] & 0xffc0) === 0xfe80) return PRIVATE; // link-local fe80::/10
    if ((g[0] & 0xffc0) === 0xfec0) return PRIVATE; // site-local fec0::/10
    if ((g[0] & 0xfe00) === 0xfc00) return PRIVATE; // unique local fc00::/7
    if ((g[0] & 0xff00) === 0xff00) return PRIVATE; // multicast ff00::/8
    if (g[0] === 0x2002) return PRIVATE; // 6to4 2002::/16 (embeds an IPv4 address)
    if (g[0] === 0x2001 && g[1] < 0x200) return PRIVATE; // IETF protocol assignments 2001::/23, incl. Teredo 2001::/32
    if (g[0] === 0x2001 && g[1] === 0x0db8) return PRIVATE; // documentation 2001:db8::/32
    if (g[0] === 0x0100 && zero(1, 4)) return PRIVATE; // discard-only 100::/64
    if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return PRIVATE; // local-use NAT64 64:ff9b:1::/48
    // IPv4 carried inside IPv6: v4-mapped (::ffff:a.b.c.d), v4-translated
    // (::ffff:0:a.b.c.d), the deprecated v4-compatible form (::a.b.c.d) and
    // NAT64 (64:ff9b::a.b.c.d).
    const embedded =
      (zero(0, 5) && g[5] === 0xffff) ||
      (zero(0, 4) && g[4] === 0xffff && g[5] === 0) ||
      zero(0, 6) ||
      (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6));
    if (embedded) {
      const v4 = `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
      return isPrivateIPv4(v4) ? PRIVATE : null;
    }
    return null;
  }

  return isPrivateIPv4(value) ? PRIVATE : null;
}

/**
 * Canonical, lower-case form of a target host as a URL parser sees it.
 * IPv6 literals come back in brackets. Returns "" if it does not parse.
 */
function canonicalHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, "");
  const literal = h.includes(":") ? `[${h}]` : h;
  try {
    return new URL(`http://${literal}/`).hostname;
  } catch {
    return "";
  }
}

/** The eight 16-bit groups of a canonical (URL-serialized) IPv6 address, or null. */
function ipv6Groups(v6) {
  const halves = v6.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;
  const parts = [...head, ...Array(fill).fill("0"), ...tail];
  if (parts.length !== 8 || !parts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) return null;
  return parts.map((p) => parseInt(p, 16));
}

function isPrivateIPv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) {
    return false;
  }
  const [a, b, c] = parts.map((p) => parseInt(p, 10));
  if (parts.some((p) => parseInt(p, 10) > 255)) return false;

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0.0/24, TEST-NET-1
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && b >= 18 && b <= 19) return true; // benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}
