# cowork-tunnel

SSH to your own servers from environments whose only outbound path is HTTPS.

## Why this exists

Anthropic Cowork sessions used to run locally, where SSH worked like it does anywhere else. They moved to cloud-only, and cloud sessions have no outbound path except HTTPS — so `ssh myserver` stopped working, and with it every workflow built on it: deploying, tailing logs, `git push` over SSH, running a build on a bigger box.

This puts that back. It carries SSH over a WebSocket, which is the one thing an HTTPS-only egress path reliably passes, so you get a normal SSH session to machines you already own.

Nothing here is specific to Cowork. Any environment that permits HTTPS and blocks port 22 — a locked-down CI runner, a corporate proxy, a hotel network — has the same problem and the same fix.

## Scope

Be clear about what this is and isn't:

- It connects to **servers you control**, using **your own SSH keys**.
- SSH authentication is unchanged and still required end to end. This defeats no authentication anywhere — the far end's sshd is as strict as you configured it.
- It changes the *transport* SSH travels over. Nothing else.

The relay is a byte pipe. Because SSH encrypts end to end, the relay only ever sees ciphertext — it cannot read or alter your session.

## Three Options

| Option | Install on | Reach | Best for |
|--------|-----------|-------|----------|
| **Standalone** | Each server | That server only | Single server, simplest setup |
| **Universal** | One server | Any server from there | Multiple servers, one install |
| **Cloudflare Worker** | Nothing | Any server | Zero infrastructure, serverless |

All three options use the same client (`client/ws_proxy.py`).

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

## Quick Start

### Client (in the restricted environment)

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
| `WS_HOST` / `WS_PORT` | `127.0.0.1` / `8765` | Listen address |
| `MAX_CONNECTIONS` | `10` | Concurrent tunnels |
| `RATE_LIMIT` | `20` | New connections per minute (shared bucket) |
| `ALLOWED_HOSTS` | *(empty)* | Hostnames, IPs, or CIDRs. Empty = any target |
| `BLOCK_PRIVATE` | off | Refuse private/loopback targets |
| `DEFAULT_PORT` | `22` | Port used when the target omits one |

`standalone.py` takes the same variables minus the target-related ones, plus `SSH_HOST` / `SSH_PORT` for the local sshd.

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

## Architecture

```
Standalone:
  restricted env --> WSS/443 --> nginx --> relay (localhost:8765) --> sshd (localhost:22)

Universal:
  restricted env --> WSS/443 --> nginx --> relay (localhost:8765) --> TCP --> any-server:22

Cloudflare:
  restricted env --> WSS/443 --> CF Edge --> Worker --> TCP --> any-server:22
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

    # Universal relay
    location /ssh {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        access_log off;              # the token is in the query string
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    # Standalone relay, if you run both on one host
    location /ssh-standalone {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        access_log off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
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
printf 'RELAY_TOKEN=%s\nWS_PORT=8765\n' "$TOKEN" | sudo tee /etc/cowork-tunnel/universal.env  >/dev/null
printf 'RELAY_TOKEN=%s\nWS_PORT=8766\n' "$TOKEN" | sudo tee /etc/cowork-tunnel/standalone.env >/dev/null
sudo chmod 600 /etc/cowork-tunnel/*.env

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

**Self-signed cert rejected (503 with TLS_error):** The egress proxy validates your relay's certificate. Use a real cert — see the sslip.io trick in the setup section above.

**Connection reset by peer during TLS:** An explicit `HTTPS_PROXY` in the environment interferes. The client clears it automatically; if you're using a custom client, unset `HTTPS_PROXY` before connecting.

**"Pipe transport is only for pipes":** `ws_proxy.py` is designed to run as an SSH ProxyCommand, not standalone. Always use it with `ssh -o 'ProxyCommand=...'`.

**`Error: relay rejected the token`:** The token the client sent doesn't match `RELAY_TOKEN` on the relay. Note that the relay accepts the WebSocket upgrade and *then* closes it with code 4003, so this shows up as a rejection after connect, not a failed connect.

**`Error: target host not allowed by the relay`:** `ALLOWED_HOSTS` is set and your target isn't in it, or `BLOCK_PRIVATE` is on and the target resolves to a private address. Add the host to `ALLOWED_HOSTS` — an explicit entry overrides `BLOCK_PRIVATE`.

## Testing

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 tests/test_all.py        # add -v for per-check detail
```

The suite imports the relay scripts for unit tests and spawns them as real subprocesses for integration tests, so it covers the code that actually ships. It runs fully offline — every target is a loopback address or an IP literal. CI runs it on Python 3.10–3.12, plus `shellcheck` on the bootstrap script and a syntax check on the Worker.

## Design notes: why WebSocket, and why the setup looks like this

Two constraints drove the whole design. Neither is exotic — most HTTPS-only environments impose some version of them — but together they rule out the simpler approaches, and knowing them explains the setup steps that otherwise look arbitrary.

**A plain TCP tunnel on 443 doesn't survive.** An HTTPS-only egress path generally isn't a port filter; it's a proxy that understands HTTP and terminates TLS. Raw bytes to port 443 aren't HTTPS and get dropped. A WebSocket upgrade is a real HTTP request that negotiates into a bidirectional byte stream, which is exactly the shape SSH needs and exactly what such a proxy will carry. That's the whole reason for the WebSocket layer — it isn't obfuscation, it's the only transport that fits both ends.

**The proxy validates your relay's certificate, so self-signed won't do.** TLS is typically re-signed in transit, which is why the client sets `verify_mode = CERT_NONE`: it would otherwise reject a certificate it was never meant to see. But the intermediary still checks the certificate *your relay* presents, and rejects an untrusted one — usually surfacing as an opaque `503`. Hence the Let's Encrypt requirement, and the sslip.io trick above if you don't own a domain.

There is also often an explicit `HTTPS_PROXY` in the environment. The `websockets` library doesn't speak `CONNECT`, so `ws_proxy.py` clears those variables and connects directly.

**What that costs you.** Since the client can't verify the relay's certificate, someone positioned between the two could read the bearer token in transit. Your SSH session is unaffected — it's encrypted end to end and host key verification still applies, so the tunnel operator and any observer see only ciphertext. The token is the exposed item, which is why it's worth rotating if you suspect it leaked.

## License

MIT
