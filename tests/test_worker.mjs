#!/usr/bin/env node
/**
 * Test suite for the Cloudflare Worker's HTTP proxy path.
 *
 * The Worker cannot run under Node as written: it imports `cloudflare:sockets`,
 * which only exists in the Workers runtime. Rather than leave the file untested,
 * this harness loads the real source with that single import specifier
 * redirected to a stub, then calls the exported fetch handler directly. Node 18+
 * supplies the rest of the runtime the proxy path uses -- fetch, Request,
 * Response, Headers, atob/btoa -- from the same web-standard implementations
 * Workers exposes.
 *
 * Scope: the HTTP proxy path only. The SSH bridge needs real TCP sockets and a
 * real WebSocketPair, so it is out of reach here and stays reviewed by hand.
 *
 * Usage:
 *   node tests/test_worker.mjs
 *   node tests/test_worker.mjs -v
 */

import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";

const VERBOSE = process.argv.includes("-v");
const REPO = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const TOKEN = "test-token-2f8a1c";

let passed = 0;
const failed = [];

function check(name, ok, detail = "") {
  if (ok) {
    passed++;
    if (VERBOSE) console.log(`  [PASS] ${name}${detail ? ` -- ${detail}` : ""}`);
  } else {
    failed.push([name, detail]);
    console.log(`  [FAIL] ${name}${detail ? ` -- ${detail}` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// Load the Worker with cloudflare:sockets stubbed out
// ---------------------------------------------------------------------------
const SOCKET_STUB =
  "data:text/javascript," +
  encodeURIComponent(
    "export function connect(){throw new Error('cloudflare:sockets is not " +
      "exercised by these tests');}"
  );

async function loadWorker() {
  const source = await readFile(path.join(REPO, "cloudflare", "worker.js"), "utf8");
  const patched = source.replace(/from\s+["']cloudflare:sockets["']/, `from "${SOCKET_STUB}"`);
  if (patched === source) {
    throw new Error("could not redirect the cloudflare:sockets import");
  }
  const url = "data:text/javascript;base64," + Buffer.from(patched).toString("base64");
  return (await import(url)).default;
}

// Workers exposes crypto.subtle.timingSafeEqual; Node does not.
if (typeof crypto.subtle.timingSafeEqual !== "function") {
  crypto.subtle.timingSafeEqual = (a, b) => {
    const x = new Uint8Array(a);
    const y = new Uint8Array(b);
    if (x.length !== y.length) return false;
    let diff = 0;
    for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
    return diff === 0;
  };
}

// ---------------------------------------------------------------------------
// Mock upstream, mirroring the routes the Python suite uses
// ---------------------------------------------------------------------------
function startUpstream() {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname === "/json") {
      const body = JSON.stringify({ greeting: "hello", source: "mock" });
      res.writeHead(200, { "Content-Type": "application/json", "X-Custom-Header": "test-value" });
      res.end(body);
    } else if (url.pathname === "/echo") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        res.writeHead(200, {
          "Content-Type": req.headers["content-type"] || "application/octet-stream",
        });
        res.end(body);
      });
    } else if (url.pathname === "/echo-headers") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(req.headers));
    } else if (url.pathname === "/cookies") {
      res.writeHead(200, {
        "Set-Cookie": ["a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/"],
        "Content-Type": "text/plain",
      });
      res.end("ok");
    } else if (url.pathname === "/dupe-headers") {
      res.writeHead(200, { "X-Multi": ["one", "two"], "Content-Type": "text/plain" });
      res.end("ok");
    } else if (url.pathname === "/redirect") {
      res.writeHead(302, { Location: "/json" });
      res.end();
    } else if (url.pathname === "/big") {
      // ?bytes=N sets the size. ?chunked=1 sends it without a Content-Length,
      // which is what a streamed response looks like -- the pre-check has
      // nothing to read, so the post-read guard is the only thing that can
      // catch it.
      const size = parseInt(url.searchParams.get("bytes") || "1024", 10);
      const payload = Buffer.alloc(size, 0x41);
      res.writeHead(200, { "Content-Type": "application/octet-stream" });
      if (url.searchParams.get("chunked") === "1") {
        res.write(payload.subarray(0, Math.floor(size / 2)));
        res.end(payload.subarray(Math.floor(size / 2)));
      } else {
        res.end(payload);
      }
    } else if (url.pathname === "/error500") {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const ENV = { RELAY_TOKEN: TOKEN };

function proxyRequest(envelope, { token = TOKEN, raw = null } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return new Request("https://relay.example.com/proxy", {
    method: "POST",
    headers,
    body: raw === null ? JSON.stringify(envelope) : raw,
  });
}

async function callProxy(worker, envelope, opts) {
  const response = await worker.fetch(proxyRequest(envelope, opts), ENV);
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

function decode(b64) {
  return Buffer.from(b64 || "", "base64");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
async function main() {
  console.log("=== cowork-tunnel Worker test suite ===");
  const worker = await loadWorker();
  const { server, port } = await startUpstream();
  const base = `http://127.0.0.1:${port}`;

  try {
    console.log("\nRouting:");
    let res = await worker.fetch(new Request("https://relay.example.com/health"), ENV);
    let body = await res.json();
    check("GET /health returns 200", res.status === 200, `got ${res.status}`);
    check(
      "health advertises ssh and proxy",
      body.capabilities?.includes("ssh") && body.capabilities?.includes("proxy"),
      JSON.stringify(body)
    );

    res = await worker.fetch(
      new Request("https://relay.example.com/proxy", { method: "GET" }),
      ENV
    );
    check("GET /proxy returns 405", res.status === 405, `got ${res.status}`);
    check("405 body is JSON", (await res.json()).error === "Method not allowed");

    res = await worker.fetch(new Request("https://relay.example.com/"), ENV);
    check("non-upgrade request returns 426", res.status === 426, `got ${res.status}`);

    console.log("\nAuth:");
    let out = await callProxy(worker, { url: `${base}/json`, method: "GET" }, { token: "" });
    check("missing token returns 401", out.status === 401, `got ${out.status}`);
    check("401 body is JSON", out.body?.error === "Forbidden", JSON.stringify(out.body));

    out = await callProxy(worker, { url: `${base}/json`, method: "GET" }, { token: "WRONG" });
    check("wrong token returns 401", out.status === 401, `got ${out.status}`);

    res = await worker.fetch(proxyRequest({ url: `${base}/json`, method: "GET" }), {});
    check("missing RELAY_TOKEN returns 500", res.status === 500, `got ${res.status}`);

    console.log("\nForwarding:");
    out = await callProxy(worker, { url: `${base}/json`, method: "GET" });
    check("GET forwards and returns 200", out.status === 200, `got ${out.status}`);
    check("upstream status is reported", out.body?.status === 200, JSON.stringify(out.body));
    check(
      "body round-trips",
      JSON.parse(decode(out.body?.body_b64).toString()).greeting === "hello",
      decode(out.body?.body_b64).toString().slice(0, 60)
    );
    check(
      "response headers are preserved",
      out.body?.headers?.["x-custom-header"] === "test-value",
      JSON.stringify(out.body?.headers)
    );

    const text = JSON.stringify({ message: "test post" });
    out = await callProxy(worker, {
      url: `${base}/echo`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: text,
    });
    check("POST body is forwarded", decode(out.body?.body_b64).toString() === text,
      decode(out.body?.body_b64).toString().slice(0, 60));

    const binary = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    out = await callProxy(worker, {
      url: `${base}/echo`,
      method: "POST",
      body_b64: binary.toString("base64"),
    });
    check("binary body_b64 round-trips", decode(out.body?.body_b64).equals(binary),
      `got ${decode(out.body?.body_b64).length} bytes`);

    // Proxy-Authorization and Trailer are hop-by-hop and, unlike Connection,
    // are not re-added by the outbound transport -- so their absence at the
    // target is real evidence the worker dropped them.
    out = await callProxy(worker, {
      url: `${base}/echo-headers`,
      method: "GET",
      headers: {
        "X-Test-Header": "forwarded-value",
        "Proxy-Authorization": "Basic c2hvdWxkLW5vdC1sZWFr",
        Trailer: "X-Checksum",
      },
    });
    const echoed = JSON.parse(decode(out.body?.body_b64).toString());
    check("custom headers reach the target", echoed["x-test-header"] === "forwarded-value",
      JSON.stringify(echoed));
    check("hop-by-hop Proxy-Authorization is stripped",
      echoed["proxy-authorization"] === undefined,
      `proxy-authorization=${echoed["proxy-authorization"]}`);
    check("hop-by-hop Trailer is stripped", echoed.trailer === undefined,
      `trailer=${echoed.trailer}`);

    out = await callProxy(worker, {
      url: `${base}/echo-headers`,
      method: "GET",
      headers: { "User-Agent": "envelope-agent" },
    });
    check("the envelope's User-Agent reaches the target verbatim",
      JSON.parse(decode(out.body?.body_b64).toString())["user-agent"] === "envelope-agent",
      JSON.parse(decode(out.body?.body_b64).toString())["user-agent"]);
    // Deliberately not asserting what a target sees when the envelope carries no
    // User-Agent. The Workers runtime adds none -- which is why a bare request
    // to GitHub comes back 403 -- while Node's fetch stamps "node" on it. That
    // gap belongs to the harness, not the Worker, so asserting either way here
    // would be testing Node. The client supplies the default instead.

    out = await callProxy(worker, { url: `${base}/error500`, method: "GET" });
    check("target 500 passes through", out.body?.status === 500, JSON.stringify(out.body));

    out = await callProxy(worker, { url: "http://127.0.0.1:1/nothing", method: "GET" });
    check("unreachable target returns 502", out.status === 502, `got ${out.status}`);
    check("502 body is JSON", typeof out.body?.error === "string", JSON.stringify(out.body));

    console.log("\nResponse fidelity:");
    out = await callProxy(worker, { url: `${base}/redirect`, method: "GET" });
    check("redirect is followed", out.body?.status === 200, JSON.stringify(out.body?.status));
    check("redirect sets redirected", out.body?.redirected === true, `${out.body?.redirected}`);
    check("redirect reports final_url", String(out.body?.final_url).endsWith("/json"),
      `${out.body?.final_url}`);

    out = await callProxy(worker, { url: `${base}/cookies`, method: "GET" });
    check("Set-Cookie is returned as a list", Array.isArray(out.body?.set_cookie)
      && out.body.set_cookie.length === 2, JSON.stringify(out.body?.set_cookie));
    check("cookies are not comma-joined",
      (out.body?.set_cookie || []).some((c) => c.startsWith("b=2;")),
      JSON.stringify(out.body?.set_cookie));
    check("Set-Cookie is kept out of the header object",
      !("set-cookie" in (out.body?.headers || {})), JSON.stringify(out.body?.headers));

    out = await callProxy(worker, { url: `${base}/dupe-headers`, method: "GET" });
    check("duplicate headers are joined with ', '",
      out.body?.headers?.["x-multi"] === "one, two", `${out.body?.headers?.["x-multi"]}`);

    console.log("\nMalformed input:");
    out = await callProxy(worker, null, { raw: "not-json" });
    check("invalid JSON returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, null, { raw: "[]" });
    check("non-object envelope returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, { method: "GET" });
    check("missing url returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, { url: `${base}/json` });
    check("missing method returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, { url: `${base}/json`, method: "GET HTTP/1.1" });
    check("invalid method returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, { url: "not-a-url", method: "GET" });
    check("unparseable url returns 400", out.status === 400, `got ${out.status}`);

    for (const scheme of ["file:///etc/passwd", "ftp://127.0.0.1/x", "data:text/plain,hi"]) {
      out = await callProxy(worker, { url: scheme, method: "GET" });
      check(`${scheme.split(":")[0]}: scheme returns 400`, out.status === 400,
        `got ${out.status}`);
    }

    out = await callProxy(worker, {
      url: `${base}/echo`,
      method: "POST",
      body_b64: "!!!not-base64!!!",
    });
    check("invalid body_b64 returns 400, not 500", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, {
      url: `${base}/json`,
      method: "GET",
      headers: { "Bad Name": "value" },
    });
    check("invalid header name returns 400", out.status === 400, `got ${out.status}`);

    out = await callProxy(worker, {
      url: `${base}/echo`,
      method: "POST",
      body_b64: Buffer.alloc(9 * 1024 * 1024, 0x41).toString("base64"),
    });
    check("oversized body returns 413", out.status === 413, `got ${out.status}`);

    console.log("\nResponse size cap:");
    // Driven down via env so the test does not have to move 32 MiB. Without a
    // cap the isolate holds the body three times over during base64 encoding
    // and dies at ~40 MB with nothing the caller can read.
    const capped = { RELAY_TOKEN: TOKEN, MAX_RESPONSE_BODY: "1024" };
    let res2 = await worker.fetch(
      proxyRequest({ url: `${base}/big?bytes=4096`, method: "GET" }),
      capped
    );
    let body2 = await res2.json();
    check("oversized response returns 502", res2.status === 502, `got ${res2.status}`);
    check("502 names the limit", /exceeds 1024 bytes/.test(body2.error || ""),
      JSON.stringify(body2));

    res2 = await worker.fetch(
      proxyRequest({ url: `${base}/big?bytes=512`, method: "GET" }),
      capped
    );
    body2 = await res2.json();
    check("response under the cap still passes", res2.status === 200, `got ${res2.status}`);
    check("under-cap body is intact", decode(body2.body_b64).length === 512,
      `got ${decode(body2.body_b64).length} bytes`);

    // A streamed response declares no Content-Length, so the pre-check cannot
    // fire and the guard on bytes actually received is all there is.
    res2 = await worker.fetch(
      proxyRequest({ url: `${base}/big?bytes=4096&chunked=1`, method: "GET" }),
      capped
    );
    check("oversized response with no Content-Length is still caught",
      res2.status === 502, `got ${res2.status}`);

    console.log("\nLogging:");
    const lines = [];
    const realLog = console.log;
    console.log = (...args) => lines.push(args.join(" "));
    try {
      await callProxy(worker, { url: `${base}/json`, method: "GET" });
      await callProxy(worker, { url: `${base}/json`, method: "GET" }, { token: "WRONG" });
    } finally {
      console.log = realLog;
    }
    check("successful proxy requests are logged",
      lines.some((l) => l.includes("[proxy] GET") && l.includes("-> 200")),
      JSON.stringify(lines));
    check("auth failures are logged",
      lines.some((l) => l.includes("401 auth failed")), JSON.stringify(lines));
    check("logs do not contain the full target URL",
      !lines.some((l) => l.includes("/json")), JSON.stringify(lines));
  } finally {
    server.close();
  }

  const total = passed + failed.length;
  if (failed.length) {
    console.log(`\n${passed}/${total} checks passed, ${failed.length} FAILED:`);
    for (const [name, detail] of failed) {
      console.log(`  - ${name}${detail ? ` (${detail})` : ""}`);
    }
    process.exit(1);
  }
  console.log(`\n${passed}/${total} checks passed -- ALL PASS`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
