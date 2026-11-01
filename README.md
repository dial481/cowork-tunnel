# cowork-tunnel

SSH and HTTP proxy for environments whose only outbound path is HTTPS.

## Why this exists

Anthropic Cowork sessions used to run locally, where SSH worked like it does anywhere else. They moved to cloud-only, and cloud sessions have no outbound path except HTTPS — so `ssh myserver` stopped working, and with it every workflow built on it: deploying, tailing logs, `git push` over SSH, running a build on a bigger box. Beyond SSH, the sandbox also intercepts some HTTPS requests — GitHub API calls, Reddit, and other destinations can be unreliable or blocked.

This puts that back. Two modes on one deployment:

1. **SSH tunneling** -- carries SSH over a WebSocket, which is the one thing an HTTPS-only egress path reliably passes, so you get a normal SSH session to machines you already own.
2. **HTTP forwarding** -- forwards arbitrary HTTP requests through the relay, bypassing HTTPS interception for GitHub API, package registries, or any other destination.

Nothing here is specific to Cowork. Any environment that permits HTTPS and blocks port 22 or intercepts HTTPS — a locked-down CI runner, a corporate proxy, a hotel network — has the same problem and the same fix.

## Scope

Be clear about what this is and isn't:

- **SSH**: It connects to **servers you control**, using **your own SSH keys**. SSH authentication is unchanged and still required end to end. This defeats no authentication anywhere — the far end's sshd is as strict as you configured it. It changes the *transport* SSH travels over. Nothing else. The relay is a byte pipe. Because SSH encrypts end to end, the relay only ever sees ciphertext — it cannot read or alter your session.
- **HTTP proxy**: It forwards HTTP requests through the relay. The relay sees the plaintext of your requests (URLs, headers, bodies). Use it for API calls that the sandbox blocks, not for passing secrets you wouldn't trust the relay operator with. Upstream credentials (like GitHub PATs) travel in the envelope headers — the relay forwards them but does not store them.

## Three Options

| Option | Install on | Reach | Best for |
|--------|-----------|-------|----------|
| **Standalone** | Each server | That server only | Single server, simplest setup |
| **Universal** | One server | Any server from there | Multiple servers, one install |
| **Cloudflare Worker** | Nothing | Any server | Zero infrastructure, serverless |

All three options use the same SSH client (`client/ws_proxy.py`) and the same HTTP proxy client (`client/http_proxy.py`).

## Security Model — Read This First

**The bearer token is the access control.** By default the universal relay and the Cloudflare Worker will open a TCP connection to *any* host and port you name. That is deliberate: a jump host that cannot reach your private network is not a jump host. But it means the token is the only thing standing between the internet and an arbitrary TCP proxy running on your server or your Cloudflare account.

Treat the token exactly like an SSH private key:

- Generate it with `secrets.token_urlsafe(32)`, never by hand.
- Store it in a root-owned `600` file or a Cloudflare secret, never in the repo.
- Rotate it the moment you think it has been exposed.
- If it leaks, someone can relay traffic through your infrastructure — port scans and SSH brute force against third parties will be attributed to you.

Two locks protect a session, not one:

1. **Bearer token** on the WebSocket upgrade — the relay refuses before any TCP connection is made.
2. **SSH key auth** on the target server — unchanged, still required, still end to end.

### What is and isn't protected

| Control | Standalone | Universal | Cloudflare Worker |
|---|---|---|---|
| Timing-safe token comparison | yes | yes | yes (SHA-256 + `timingSafeEqual`) |
| Target allowlist (`ALLOWED_HOSTS`) | n/a | optional, off by default | optional, off by default |
| Private-address guard (`BLOCK_PRIVATE`) | n/a | optional, off by default | optional, off by default (lexical only) |
| Concurrent connection cap | yes | yes | **no** |
| Connection rate limit | yes, see below | yes, see below | **no** |

**The rate limit is a single shared bucket, not per-client.** It keys on the peer address, and behind nginx every peer is `127.0.0.1`. For the single-user case this project targets, that is fine — it is a brake on runaway reconnect loops, not a multi-tenant control. Do not rely on it to isolate users from each other.

**`BLOCK_PRIVATE` is a guardrail, not a boundary.** In the Python relays it resolves the target once and checks the resolved address, then connects to that exact address — so a DNS rebind between check and connect cannot slip past. In the Cloudflare Worker it is a lexical check on the target string only, because Workers has no resolver API; a hostname pointing at a private address is not caught there. On Cloudflare this matters little (a Worker's egress cannot reach your LAN and there is no instance metadata service to hit), but do not mistake it for enforcement.

Entries in `ALLOWED_HOSTS` are treated as a deliberate decision and override `BLOCK_PRIVATE`, so allowlisting an internal host works as you would expect.

**The token travels in the query string** because some proxies strip `Authorization` headers. It is also sent as a header. Query strings land in access logs — the shipped nginx config sets `access_log off` for the tunnel location, and the Cloudflare Worker's request logs will contain it. Factor that into where you let logs go.

**The client does not check the relay's certificate, and ignores `HTTPS_PROXY`.** That is what lets it work in Cowork, where the network rewrites TLS. It is a known gap, and a low-priority one:

- What it exposes: someone who can pose as your relay (they would need to control DNS, the network or the proxy you are on) gets the relay token. They can also answer the tunnel with a server of their own. Whether that works depends on the host key check:
  - If ssh already knows the server's host key (a `known_hosts` entry, or `StrictHostKeyChecking yes` with the key pinned), a fake server is refused before anything is sent. The impostor gets the token and nothing else.
  - If it doesn't, for example a first connection with `StrictHostKeyChecking accept-new` or `no`, ssh accepts the impostor's host key. Everything you then send goes to the impostor: the commands you run, files you upload, and a password if you use one. What comes back can be faked.
- What it never exposes: your SSH private key. Key login sends a signature tied to that one session, never the key, and the signature can't be replayed against your real server. The exception is agent forwarding (`ForwardAgent yes`), which lets the other end use your agent while you're connected, so leave it off.
- What a stolen token costs: free use of your relay as a TCP and HTTP proxy, attributed to you, until you rotate it.

**The real protection is the host key check, whichever client you use.** A relay that verifies TLS still connects to your server over the open internet, and anyone who can hijack that leg (DNS for the server's name, routing) can pose as the server in exactly the same way. Put each server's host key in `known_hosts` before the first connection, and use `StrictHostKeyChecking yes`. bootstrap.sh does not do this for you.

- If you can read the key on the server (`cat /etc/ssh/ssh_host_ed25519_key.pub`), add that line, prefixed with the host name, to `~/.ssh/known_hosts`. For example `server.example.com ssh-ed25519 AAAA...`, or `[server.example.com]:2222 ssh-ed25519 AAAA...` for a non-standard port.
- If you only have the fingerprint (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server, or your provider's console shows it), collect the key with `ssh-keyscan -t ed25519 server.example.com > key.txt` and run `ssh-keygen -lf key.txt`. Add `key.txt` to `known_hosts` only if the two fingerprints match. Through the tunnel, `ssh-keyscan` needs the same ProxyCommand, so it is often easier to do this from a machine that can reach the server directly.

Also worth doing: rotate the token if you suspect anything, and narrow the relay with `ALLOWED_HOSTS`. A client that verifies TLS and keeps the proxy may come later as an opt-in; it is deliberately not the default, because the default has to work in Cowork.

**Large downloads to a slow client are buffered in the Worker.** A Workers WebSocket gives no way to tell how far behind the client is, so the Worker cannot slow the target down. For ssh, scp, sftp and rsync this does not matter: SSH's own flow control keeps the target from sending more than the client has room for. Measured in workerd, a 300 MB scp download throttled to 5 MB/s used no more Worker memory than an unthrottled one. Tunnelling a protocol with no flow control of its own to a slow client could run the Worker out of memory and drop the connection. Low priority; a fix needs the client to acknowledge what it has received.

## Quick Start

### Client (in the restricted environment)

If pip works where you are, this is the short path:

```bash
pip install cowork-tunnel

export COWORK_RELAY_URL="wss://your-relay.example.com/ssh"
export COWORK_RELAY_TOKEN="your-secret-token"

cowork-tunnel-http GET https://api.github.com/zen --raw
ssh -o 'ProxyCommand=cowork-tunnel-ssh' user@server
```

The package installs two commands and pulls in `websockets` for you. The rest of
this section is the fallback for environments where pip is blocked — the clients
are standalone files by design and `bootstrap.sh` fetches them individually.

```bash
# Install deps (one time per session)
apt-get install -y openssh-client
pip install websockets --break-system-packages

# Set relay URL and token
export COWORK_RELAY_URL="wss://your-relay.example.com/ssh"
export COWORK_RELAY_TOKEN="your-secret-token"

# SSH as normal, with ProxyCommand
ssh -o 'ProxyCommand=python3 client/ws_proxy.py' user@server

# Or for universal/cloudflare mode, specify target in URL
export COWORK_RELAY_URL="wss://jump.example.com/ssh?target=192.168.1.1:22"
ssh -o 'ProxyCommand=python3 client/ws_proxy.py' user@server
```

Or use the bootstrap script:
```bash
export COWORK_RELAY_URL="wss://your-relay.example.com/ssh"
export COWORK_RELAY_TOKEN="your-token"
curl -fsSL https://raw.githubusercontent.com/dial481/cowork-tunnel/main/client/bootstrap.sh | bash
ssh user@server  # just works
```

The bootstrap script writes a `Host *` block to `~/.ssh/config`, which routes **all** SSH in that session through the tunnel. Re-running it replaces that block rather than appending a second one. Delete the marked block to disable it.

Piping a script from the internet into `bash` runs whatever that URL returns. Read it first if that matters to you; it is short.

The script takes three optional overrides:

| Variable | Default | Meaning |
|---|---|---|
| `COWORK_TUNNEL_DIR` | `/tmp/cowork-tunnel` | Where the client scripts are installed |
| `COWORK_TUNNEL_PYTHON` | *(unset)* | An interpreter you manage — a venv, a conda env, anything. Set it and bootstrap installs nothing and creates nothing |
| `COWORK_TUNNEL_REF` | `main` | Branch, tag or commit to fetch the clients from |
| `COWORK_TUNNEL_REPO_RAW` | GitHub raw URL | A different origin entirely, for a fork or a mirror |

`ws_proxy.py` needs the `websockets` package; `http_proxy.py` needs nothing beyond the standard library. If your `python3` already has `websockets`, bootstrap uses it as-is. If it does not, bootstrap builds a venv under `COWORK_TUNNEL_DIR` rather than installing into system Python — distro Pythons are marked externally-managed (PEP 668) and `pip --break-system-packages` exists to override that guard, which is not a thing an installer should do to you by default. Set `COWORK_TUNNEL_PYTHON` to opt out entirely and manage the environment yourself. Failing to install `websockets` is a warning, not an error: the HTTP proxy still installs and works.

Keep the clients and the relay on the same revision. Installing a client from `main` while running a relay from a branch is how you get behaviour that matches neither.

### HTTP Proxy

The HTTP proxy forwards arbitrary HTTP requests through the relay. It uses the same relay URL and token as the SSH tunnel — one hostname, one token, routed by path. Unlike the SSH client it needs no `websockets` install: it is a plain HTTPS POST and uses only the standard library.

```bash
# Set relay URL and token (same as SSH)
export COWORK_RELAY_URL="https://your-relay.example.com"
export COWORK_RELAY_TOKEN="your-secret-token"

# Simple GET
python3 client/http_proxy.py GET https://api.github.com/repos/owner/repo

# POST with headers and body
python3 client/http_proxy.py POST https://api.github.com/repos/owner/repo/issues \
  -H "Authorization: token ghp_xxx" \
  -H "Content-Type: application/json" \
  -d '{"title": "Bug report"}'

# Pipe output (--raw suppresses status/headers on stderr)
python3 client/http_proxy.py GET https://example.com/data.json --raw | jq .

# Send a binary body from a file (-b), rather than a string (-d)
python3 client/http_proxy.py PUT https://example.com/upload -b ./payload.bin
```

Flags: `-H` adds a header (repeatable), `-d` sends a string body, `-b` sends a file as the body (binary safe), `--raw` prints only the response body so it can be piped.

As a library (`from cowork_tunnel.http_proxy import ...` when pip-installed, `from http_proxy import ...` when using the file directly):
```python
from cowork_tunnel.http_proxy import relay_fetch

response = relay_fetch(
    method="GET",
    url="https://api.github.com/repos/owner/repo",
    headers={"Authorization": "token ghp_xxx"},
)
print(response["status"])   # 200
print(response["body"])     # b'{"id": 123, ...}'
```

The client auto-detects the relay URL format: if `COWORK_RELAY_URL` is a WebSocket URL like `wss://host/ssh?target=...`, it extracts the base host and appends `/proxy`.

The response dict carries `status`, `headers`, `body` (bytes) and `body_b64`. Two fields appear only when relevant:

- `set_cookie` — a list of the target's `Set-Cookie` headers. Cookies are kept out of the flat `headers` dict on purpose: repeated headers are folded together with `, `, and a cookie's `Expires` date contains a comma, so folding them produces values no client can parse.
- `redirected` / `final_url` — present when the target redirected and the final URL differs from the one you asked for.

Client environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `COWORK_RELAY_URL` | *(required)* | Relay base URL. `wss://`/`ws://` accepted; path and query are stripped |
| `COWORK_RELAY_TOKEN` | *(empty)* | Bearer token |
| `COWORK_RELAY_TIMEOUT` | `60` | Seconds to wait for the relay before giving up |
| `COWORK_RELAY_VERIFY_TLS` | off | Verify the relay's certificate. Off by default because the Cowork sandbox re-signs TLS; turn it on anywhere with a clean path to the relay |
| `COWORK_RELAY_USER_AGENT` | `cowork-tunnel` | The agent this client identifies as, both to the relay and to the target when you don't set one yourself |

The client reads `COWORK_RELAY_*` from the environment but never modifies it — proxy settings are bypassed per-request rather than by deleting `HTTPS_PROXY` process-wide.

**User-Agent.** Two different requests carry one: the hop to the relay, and the forwarded request the target sees. The client names itself on both. This is not cosmetic — Cloudflare's edge rejects urllib's default `Python-urllib/x.y` with a `403` (error 1010) before the request reaches a Worker-hosted relay at all, and GitHub answers `403` to a forwarded request carrying no agent. Set `User-Agent` in `-H`/`headers` to override what the target sees; the relays forward exactly what the envelope contains and invent nothing.

### Option 1: Standalone Relay (per server)

Install on the server you want to reach. Bridges WebSocket to local sshd.

```bash
# On the server
pip install websockets --break-system-packages
export RELAY_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "Save this token: $RELAY_TOKEN"

# Run in the foreground, or install as a systemd service (see below)
RELAY_TOKEN=$RELAY_TOKEN python3 relay/standalone.py
```

Add the nginx location block from `relay/nginx-location.conf` to proxy `/ssh` to the relay.

**TLS certificate:** The egress proxy validates the certificate your relay presents, so a self-signed one is rejected and you need a real cert. If you don't have a domain, use the **sslip.io trick** — it gives you a free domain that resolves to any IP, and Let's Encrypt will issue a cert for it:

```bash
sudo apt install certbot python3-certbot-nginx -y
# Open port 80 for the ACME challenge
sudo ufw allow 80/tcp
# Replace dashes for dots in your IP
sudo certbot --nginx -d YOUR-IP-WITH-DASHES.sslip.io
# e.g. for 203.0.113.42:
sudo certbot --nginx -d 203-0-113-42.sslip.io
```

If certbot can't auto-install, set `server_name` in your nginx config first:
```bash
sudo sed -i 's/server_name _;/server_name YOUR-IP-WITH-DASHES.sslip.io;/' /etc/nginx/sites-enabled/your-site
sudo certbot install --cert-name YOUR-IP-WITH-DASHES.sslip.io
```

### Option 2: Universal Relay (one server, reach all)

Install on ONE server. Routes to any target host:port, including hosts on that server's private network. Acts as a jump host. Needs the same nginx + TLS setup as the standalone relay (see the TLS certificate section above).

```bash
# On your jump server
pip install websockets --break-system-packages
export RELAY_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Reach anything (default)
RELAY_TOKEN=$RELAY_TOKEN python3 relay/universal.py

# Or restrict to specific targets
ALLOWED_HOSTS="server1.com,192.168.1.5,10.0.0.0/8" \
  RELAY_TOKEN=$RELAY_TOKEN python3 relay/universal.py

# Or refuse private targets entirely (public internet only)
BLOCK_PRIVATE=1 RELAY_TOKEN=$RELAY_TOKEN python3 relay/universal.py
```

Client usage adds a `target` parameter:
```bash
export COWORK_RELAY_URL="wss://jump.example.com/ssh?target=other-server.com:22"
ssh -o 'ProxyCommand=python3 client/ws_proxy.py' user@other-server
```

Targets may be `host`, `host:port`, `[v6addr]:port`, or a bare IPv6 literal. The port defaults to 22 and must be in range 1–65535.

**Environment variables**

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_TOKEN` | *(required)* | Bearer token |
| `WS_HOST` | `127.0.0.1` | Listen address for both ports |
| `WS_PORT` | `8765` | WebSocket/SSH port |
| `PROXY_PORT` | `8766` | HTTP proxy port, serving `/proxy` and `/health`. Must differ from `WS_PORT` |
| `MAX_CONNECTIONS` | `10` | Concurrent tunnels |
| `RATE_LIMIT` | `20` | New connections per minute (shared bucket) |
| `ALLOWED_HOSTS` | *(empty)* | Hostnames, IPs, or CIDRs. Empty = any target. **SSH path only** |
| `BLOCK_PRIVATE` | off | Refuse private/loopback targets. **SSH path only** |
| `DEFAULT_PORT` | `22` | Port used when the target omits one |

HTTP proxy path (`POST /proxy`):

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_RATE_LIMIT` | `120` | Proxy requests per minute (separate bucket from `RATE_LIMIT`) |
| `MAX_PROXY_BODY` | `8 MiB` | Largest request body accepted. This bounds the JSON envelope; a binary payload is base64-encoded inside it, so 8 MiB here is roughly 6 MiB of actual upload. Keep nginx's `client_max_body_size` in step |
| `MAX_RESPONSE_BODY` | `32 MiB` | Largest upstream response returned. The body is buffered and base64-encoded, so relay memory peaks at roughly 2.5× this |
| `PROXY_TIMEOUT` | `25` | Seconds to wait for the upstream target |
| `HEAD_TIMEOUT` / `BODY_TIMEOUT` | `15` / `30` | Seconds a client may take to send a request head / body before the connection is dropped |
| `INSECURE_UPSTREAM_TLS` | off | Skip certificate verification on upstream HTTPS. **Off by default** — only enable if the relay itself sits behind a TLS-intercepting gateway |

`standalone.py` takes the same variables minus the target-related ones, plus `SSH_HOST` / `SSH_PORT` for the local sshd. It is SSH-only and has no `/proxy` endpoint.

**Upstream TLS is verified.** The relay checks the target's certificate against the system trust store. The *client* skips verification when talking to the relay (the Cowork sandbox re-signs everything), but the relay's own hop to the internet is verified — that hop is what carries your forwarded credentials. `INSECURE_UPSTREAM_TLS=1` turns it off if your relay genuinely sits behind an intercepting proxy.

**`ALLOWED_HOSTS` and `BLOCK_PRIVATE` do not apply to `/proxy`.** They are TCP target controls for the SSH path. The HTTP proxy forwards to any `http(s)` URL by design. Other schemes (`file:`, `ftp:`, `data:`) are refused — without that, a token holder could read files off the relay's own disk.

**Two local ports, one public endpoint.** The universal relay listens twice: `WS_PORT` (default 8765) for WebSocket/SSH, and `PROXY_PORT` (default 8766) for `/proxy` and `/health`. Both are plaintext and both expect to sit behind nginx, which terminates TLS on 443 and routes by path. **Clients only ever reach 443** — the split is invisible to them, and neither port should be exposed directly.

If you upgrade an existing install, add the `/proxy` and `/health` location blocks pointing at 8766 and set `PROXY_PORT` in the unit's env file. Sending `/proxy` to 8765 gets a `426` from websockets. See [Design notes](#design-notes-why-the-relay-listens-twice) for why it is built this way.

### Option 3: Cloudflare Worker (serverless)

Deploy once to Cloudflare. No servers to maintain.

Runs on the **free** Workers plan — outbound TCP via `cloudflare:sockets` is not a paid-only feature. Verified by tunnelling a full SSH session and an 8 MiB transfer through a free account. What you can hit on the free plan is the daily request cap and the per-invocation CPU limit, neither of which a mostly-idle SSH tunnel comes close to.

```bash
# Install wrangler
npm install -g wrangler
wrangler login

# Deploy
cd cloudflare/
wrangler secret put RELAY_TOKEN  # paste your generated token
wrangler deploy
```

Client usage:
```bash
export COWORK_RELAY_URL="wss://cowork-tunnel.your-subdomain.workers.dev/?target=server.com:22"
ssh -o 'ProxyCommand=python3 client/ws_proxy.py' user@server
```

The Worker has no rate limit and no connection cap — Workers gives you no shared state to implement them in without a Durable Object. If that matters for your deployment, set `ALLOWED_HOSTS` and treat the token as the whole security model.

The Worker caps proxied response bodies at 32 MiB, matching the relay's `MAX_RESPONSE_BODY`. Override it with a `MAX_RESPONSE_BODY` var in `wrangler.toml`. The cap exists because the response is held three times over while it is base64-encoded — the buffer, the binary string, and the output — so an uncapped forward of a large download walks the isolate into its 128 MB memory limit and dies with nothing the caller can read. Past the cap you get a `502` naming the limit instead.

Proxied requests are logged as `[proxy] METHOD host -> status`, visible in `wrangler tail`. Host only, never the full URL: a forwarded URL can carry a token in its query string.

## Architecture

```
The client only ever reaches port 443. nginx terminates TLS and routes by path;
the universal relay's two local ports are never exposed.

SSH Tunnel:
  Standalone:   restricted env --> WSS/443 --> nginx --> :8765 relay --> sshd (localhost:22)
  Universal:    restricted env --> WSS/443 --> nginx --> :8765 relay --> TCP --> any-server:22
  Cloudflare:   restricted env --> WSS/443 --> CF Edge --> Worker --> TCP --> any-server:22

HTTP Proxy:
  Universal:    restricted env --> POST /proxy --> nginx --> :8766 relay --> any URL
  Cloudflare:   restricted env --> POST /proxy --> CF Edge --> Worker --> fetch() --> any URL
```

## SSH Config Integration

Add to `~/.ssh/config` in the restricted environment for transparent use:

```
Host *
    ProxyCommand python3 /path/to/ws_proxy.py
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

`ServerAliveInterval 60` prevents the connection from being dropped by Cloudflare's 900-second idle timeout.

## For Git

```bash
export GIT_SSH_COMMAND='ssh -o "ProxyCommand=python3 /path/to/ws_proxy.py"'
git push origin main  # works through the tunnel
```

## Full nginx Setup

The standalone and universal relays need nginx in front for TLS termination. Here's a complete server block:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Universal relay -- SSH over WebSocket
    location /ssh {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        access_log off;              # the token is in the query string
        # SSH sessions idle. Anything short and nginx closes the tunnel under you.
        proxy_read_timeout 7d;
        proxy_send_timeout 7d;
        proxy_buffering off;
    }

    # Universal relay -- HTTP proxy (note the different port)
    location /proxy {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        access_log off;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        client_max_body_size 8m;
    }

    # Health check, same port as the HTTP proxy. Optional.
    location /health {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        access_log off;
    }

    # Standalone relay, if you run both on one host. Note 8767: the universal
    # relay already occupies 8765 (SSH) and 8766 (HTTP proxy).
    location /ssh-standalone {
        proxy_pass http://127.0.0.1:8767;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        access_log off;
        proxy_read_timeout 7d;
        proxy_send_timeout 7d;
        proxy_buffering off;
    }
}

# Port 80 exists so Certbot's HTTP-01 challenge can renew the certificate.
# Without it renewal fails and the tunnel dies when the cert expires.
server {
    listen 80;
    server_name your-domain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
```

Save to `/etc/nginx/sites-enabled/cowork-tunnel`, then `sudo nginx -t && sudo systemctl reload nginx`.

Keep backups of that file *outside* `sites-enabled/` — nginx includes every file in that directory, so a `cowork-tunnel.bak` is loaded as live config and produces a "conflicting server name" warning.

See `relay/nginx-location.conf` for the location block only.

**Confirm renewal works.** A certbot timer being armed is not evidence that renewal succeeds — if port 80 is unreachable the challenge fails, and when the certificate expires the egress proxy rejects it and every tunnel stops. Prove it end to end:

```bash
sudo ufw allow 80/tcp
sudo certbot renew --dry-run     # must succeed before you trust the timer
```

## Running as a systemd service

`relay/cowork-tunnel@.service` is a templated unit — the instance name selects both the script and its config, so one file runs both relays.

```bash
# Install the scripts and the unit
sudo install -d -m 755 /opt/cowork-tunnel
sudo install -m 644 relay/universal.py relay/standalone.py /opt/cowork-tunnel/
sudo install -m 644 relay/cowork-tunnel@.service /etc/systemd/system/

# One config file per instance, root-owned and 0600. systemd reads these as
# root before dropping to User=nobody, so the relay account never needs them.
sudo install -d -m 700 /etc/cowork-tunnel
TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
# The universal relay binds two ports (8765 SSH, 8766 HTTP proxy), so the
# standalone relay goes on 8767 rather than colliding with 8766.
printf 'RELAY_TOKEN=%s\nWS_PORT=8765\nPROXY_PORT=8766\n' "$TOKEN" | sudo tee /etc/cowork-tunnel/universal.env  >/dev/null
printf 'RELAY_TOKEN=%s\nWS_PORT=8767\n' "$TOKEN" | sudo tee /etc/cowork-tunnel/standalone.env >/dev/null
# Explicit paths, not a glob: /etc/cowork-tunnel is 0700 root-owned, so a glob
# expands in your unprivileged shell, fails, and the chmod silently never runs --
# leaving the token files world-readable.
sudo chmod 600 /etc/cowork-tunnel/universal.env /etc/cowork-tunnel/standalone.env

sudo systemctl daemon-reload
sudo systemctl enable --now cowork-tunnel@universal
sudo systemctl enable --now cowork-tunnel@standalone
```

Check them with `systemctl status cowork-tunnel@universal` and `journalctl -u cowork-tunnel@universal -f`. To rotate the token, edit the env files and `sudo systemctl restart 'cowork-tunnel@*'`.

## Troubleshooting

**HTTP 503 from nginx:** The relay isn't listening. Check with `ss -tlnp | grep 8765`, then `systemctl status cowork-tunnel@universal` and `journalctl -u cowork-tunnel@universal -n 50`.

**Service sits in `activating (auto-restart)`:** The relay is exiting immediately, almost always because it can't import `websockets`. The unit runs as `User=nobody` with `ProtectHome=yes`, so packages installed into a user's home (`pip install --user`, or plain `pip install` as a normal account) are invisible to it. Give the service its own venv — see the systemd section above.

**No journal output at all from the unit:** If `journalctl` reports "No journal files were found," the host isn't persisting logs. Create the directory and restart journald: `sudo install -d -m 2755 -g systemd-journal /var/log/journal && sudo systemctl restart systemd-journald`.

**"externally-managed-environment" on pip install:** Modern Debian/Ubuntu blocks system-wide pip. Use `pip install websockets --break-system-packages`.

**Certbot times out, or the relay is unreachable even though `ufw` allows the port:** Your host firewall is not the only one. Cloud providers put a second firewall in front of the instance — DigitalOcean Cloud Firewalls, AWS security groups, GCP VPC rules — and it is invisible to `ufw status`. A *closed* port refuses instantly; a *filtered* one times out, so a timeout is the tell. Confirm at the packet level rather than guessing: run `sudo tcpdump -n -i any 'tcp port 443 and tcp[tcpflags] & tcp-syn != 0'`, then connect from somewhere off-box. No inbound SYN means the packets never arrived and the provider firewall is dropping them; open the port there too.

**Self-signed cert rejected (503 with TLS_error):** The egress proxy validates your relay's certificate. Use a real cert — see the sslip.io trick in the setup section above.

**Connection reset by peer during TLS:** An explicit `HTTPS_PROXY` in the environment interferes. The client clears it automatically; if you're using a custom client, unset `HTTPS_PROXY` before connecting.

**"Pipe transport is only for pipes":** `ws_proxy.py` is designed to run as an SSH ProxyCommand, not standalone. Always use it with `ssh -o 'ProxyCommand=...'`.

**`Error: relay rejected the token`:** The token the client sent doesn't match `RELAY_TOKEN` on the relay. The self-hosted Python relays (standalone and universal) accept the WebSocket upgrade and *then* close it with code 4003, so there this shows up as a rejection after connect, not a failed connect. The Cloudflare Worker refuses the upgrade itself with HTTP 403, so the message ends in `(403 Forbidden)`.

**`Error: relay refused the request: ...`** (Cloudflare Worker): The Worker turned the request down before connecting and said why; the text after the colon is its reason: `Target not in allowlist` (add the host to `ALLOWED_HOSTS`), a `BLOCK_PRIVATE` refusal (a private address, or an address not written in standard form, with the form to use), or `Invalid target` / `Missing target parameter` (check `?target=host:port`). Clients before 2.1.2 reported all of these as a rejected token.

**`Error: target host not allowed by the relay`** (self-hosted universal relay, close code 4002): `ALLOWED_HOSTS` is set and your target isn't in it, or `BLOCK_PRIVATE` is on and the target resolves to a private address. Add the host to `ALLOWED_HOSTS`; an explicit entry overrides `BLOCK_PRIVATE`. The Cloudflare Worker reports the same situations as `relay refused the request` instead (above).

## Testing

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 tests/test_all.py        # relays and clients; add -v for per-check detail
node tests/test_worker.mjs       # Cloudflare Worker; needs Node 18+
```

The suite imports the relay scripts for unit tests and spawns them as real subprocesses for integration tests, so it covers the code that actually ships. It runs fully offline — every target is a loopback address or an IP literal. CI runs it on Python 3.10–3.12, plus `shellcheck` on the bootstrap script and a syntax check on the Worker.

The Worker is tested too, despite having no local runtime. `tests/test_worker.mjs` loads the real `cloudflare/worker.js` with its one `cloudflare:sockets` import redirected to a stub, then calls the exported `fetch` handler directly — Node supplies the rest of what the proxy path uses (`fetch`, `Request`, `Response`, `Headers`, `atob`/`btoa`) from the same web-standard implementations Workers exposes. That covers routing, auth, forwarding, response fidelity and malformed input.

The SSH bridge is covered too. `bridge()` is module-scoped, and driving it through `fetch()` would need a `WebSocketPair` and a 101 `Response`, neither of which Node can construct — so the harness exports it from the in-memory copy and calls it directly, with `cloudflare:sockets` backed by `node:net`. `cloudflare/worker.js` on disk is never modified; `git diff` proves it. What that leaves untested is the wiring between `fetch()` and `bridge()` on the real runtime, which is exercised against a deployed Worker instead.

`websockets>=14.1` is the declared floor and CI pins that exact version in a separate job. Installing only the newest release would never prove the floor still works — and it did not: 14.0 and earlier lack `ClientConnection.close_code`, which `ws_proxy.py` needs to tell you *why* a tunnel was refused.

## Design notes: why WebSocket, and why the setup looks like this

Two constraints drove the whole design. Neither is exotic — most HTTPS-only environments impose some version of them — but together they rule out the simpler approaches, and knowing them explains the setup steps that otherwise look arbitrary.

**A plain TCP tunnel on 443 doesn't survive.** An HTTPS-only egress path generally isn't a port filter; it's a proxy that understands HTTP and terminates TLS. Raw bytes to port 443 aren't HTTPS and get dropped. A WebSocket upgrade is a real HTTP request that negotiates into a bidirectional byte stream, which is exactly the shape SSH needs and exactly what such a proxy will carry. That's the whole reason for the WebSocket layer — it isn't obfuscation, it's the only transport that fits both ends.

**The proxy validates your relay's certificate, so self-signed won't do.** TLS is typically re-signed in transit, which is why the client sets `verify_mode = CERT_NONE`: it would otherwise reject a certificate it was never meant to see. But the intermediary still checks the certificate *your relay* presents, and rejects an untrusted one — usually surfacing as an opaque `503`. Hence the Let's Encrypt requirement, and the sslip.io trick above if you don't own a domain.

There is also often an explicit `HTTPS_PROXY` in the environment. The `websockets` library doesn't speak `CONNECT`, so `ws_proxy.py` clears those variables and connects directly.

**What that costs you.** Since the client can't verify the relay's certificate, someone positioned between the two could read the bearer token in transit, and could answer with a fake SSH server. The SSH session is safe only if ssh already knows the server's host key: then a fake server is refused, and the relay operator and any observer see only ciphertext. On a first connection that accepts any key, the impostor receives what you send. See [Security Model](#security-model--read-this-first) for what is exposed in each case.

## Design notes: why the relay listens twice

Adding `POST /proxy` raised a question that looks trivial and isn't: how does one process serve both WebSocket upgrades and ordinary HTTP requests? The `websockets` library expects to own a listening socket and offers no public way to hand it a connection you have already accepted — `serve()` takes a *listening* socket, never a connected one. Nor can its `process_request` hook answer `/proxy`, because that hook never sees a request body.

Three designs were tried. The relay uses the third.

**1. Swap the protocol in-process.** Read the request head yourself, build a `ServerConnection` by hand, and attach it to the existing transport with `set_protocol()`. One socket, no copying.

It needs `ServerProtocol`'s constructor, `ServerConnection`'s constructor, the `Server` object it expects, and the way the handshake task is started — none of it public API. The first version of the v2 proxy was built this way. It worked on websockets 17.x and **broke the SSH bridge on 13.1, 14.2, 15.0 and 16.0**: four of the five versions tested. The failure mode is the bad kind — silent, total, and triggered by an unrelated `pip install -U`.

**2. Dispatch in front of a loopback websockets server.** Read the head on the public port, answer `/proxy` yourself, and for an upgrade open a second connection to a websockets server on `127.0.0.1`, replay the head, and copy bytes both ways. Public API only, one public port — but it puts a hand-written HTTP parser in front of every tunnel and copies every byte an extra time.

**3. Give each protocol its own local port.** *(chosen)* `websockets` owns `WS_PORT` outright, exactly as it did before the proxy existed, so nothing sits between a client and the library's own handshake. The HTTP handlers own `PROXY_PORT` and never see tunnel traffic. nginx routes by path, so clients still reach exactly one endpoint on 443.

This is the least code and the least cleverness: no internals, no interposed parser, and the SSH path is byte-for-byte the arrangement that shipped in v1.0.0. The cost is one more port to configure, which is why the `/proxy` and `/health` location blocks point at 8766.

### The thing that actually made it fast

All three designs measure the same — roughly 175–240 MiB/s over loopback for 100 MiB of random data. The architecture was never the bottleneck.

What *was* the bottleneck: `serve()` and `connect()` negotiate **permessage-deflate** by default, and this tunnel carries SSH. SSH is encrypted, so its bytes are indistinguishable from random and cannot compress. Every frame was being run through deflate to produce slightly *larger* output, on both ends.

| 100 MiB of random data, end to end | throughput |
|---|---|
| permessage-deflate enabled (as shipped in v1.0.0) | **12.5 MiB/s** |
| `compression=None` | **220 MiB/s** |

That is a ~17× throughput bug that was present in v1.0.0 and had nothing to do with the proxy work. It is now disabled in `universal.py`, `standalone.py`, and `ws_proxy.py` — the client declines it too, which also covers the Cloudflare path, where the edge would otherwise accept the offer. A test asserts the handshake response carries no `Sec-WebSocket-Extensions` header, so it cannot come back unnoticed.

An earlier draft of these notes blamed design 2 for a 4× slowdown. That was wrong: the measurement compared a compressed build against an uncompressed one, using a payload of repeated bytes that deflate handled unrealistically well. Real SSH traffic does not look like that.

## License

MIT
