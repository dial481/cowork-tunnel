#!/usr/bin/env bash
# Bootstrap script for new Cowork cloud sessions.
# Downloads ws_proxy.py, installs deps, and configures SSH.
#
# Usage:
#   # Set these before running:
#   export COWORK_RELAY_URL="wss://your-relay.example.com/ssh"
#   export COWORK_RELAY_TOKEN="your-secret-token"
#
#   # Then run:
#   curl -fsSL https://raw.githubusercontent.com/dial481/cowork-tunnel/main/client/bootstrap.sh | bash
#
#   # Or for universal/cloudflare mode with a default target:
#   export COWORK_RELAY_URL="wss://jump.example.com/ssh?target=192.168.1.1:22"
#
# Re-running is safe: the SSH config block is replaced, not appended again.

set -euo pipefail

# Where the client scripts are fetched from. Pinned to main by default, but
# overridable so a branch or a fork can be tested without editing this file:
#   COWORK_TUNNEL_REF=dev              -- another branch, tag or commit
#   COWORK_TUNNEL_REPO_RAW=https://... -- an entirely different origin
# The scripts must match the relay they talk to; fetching a client from main
# while running a relay from a branch is how you get mismatched behaviour.
COWORK_TUNNEL_REF="${COWORK_TUNNEL_REF:-main}"
REPO_RAW="${COWORK_TUNNEL_REPO_RAW:-https://raw.githubusercontent.com/dial481/cowork-tunnel/${COWORK_TUNNEL_REF}}"
INSTALL_DIR="${COWORK_TUNNEL_DIR:-/tmp/cowork-tunnel}"
SSH_CONFIG="${HOME}/.ssh/config"
MARKER_BEGIN="# >>> cowork-tunnel begin >>>"
MARKER_END="# <<< cowork-tunnel end <<<"

echo "[cowork-tunnel] Setting up SSH tunnel..."

# --- Validate config first, before changing anything on the machine ---------
if [ -z "${COWORK_RELAY_URL:-}" ]; then
    echo "[cowork-tunnel] ERROR: COWORK_RELAY_URL not set." >&2
    echo "  export COWORK_RELAY_URL=\"wss://your-relay.example.com/ssh\"" >&2
    exit 1
fi

if [ -z "${COWORK_RELAY_TOKEN:-}" ]; then
    echo "[cowork-tunnel] WARNING: COWORK_RELAY_TOKEN not set. Auth will fail." >&2
fi

# --- Dependencies -----------------------------------------------------------
if ! command -v ssh &>/dev/null; then
    echo "[cowork-tunnel] Installing openssh-client..."
    apt-get update -qq && apt-get install -y -qq openssh-client >/dev/null
fi

# ws_proxy.py needs the websockets package; http_proxy.py needs nothing beyond
# the standard library. TUNNEL_PYTHON is whichever interpreter can import it,
# and the SSH ProxyCommand below is written to use exactly that one.
# Set COWORK_TUNNEL_PYTHON to an interpreter you manage -- a venv, a conda env,
# anything -- and bootstrap installs nothing and creates nothing. Otherwise it
# uses the system python3 if that already has websockets, and only falls back
# to building a venv when the package is genuinely missing.
TUNNEL_PYTHON="${COWORK_TUNNEL_PYTHON:-python3}"
if [ -n "${COWORK_TUNNEL_PYTHON:-}" ]; then
    # ssh runs ProxyCommand from an arbitrary working directory, so a relative
    # path would resolve differently there than it does here. Fail now rather
    # than writing a Host * block that breaks every SSH connection on the box.
    if ! command -v "$TUNNEL_PYTHON" >/dev/null 2>&1; then
        echo "[cowork-tunnel] ERROR: COWORK_TUNNEL_PYTHON is not executable: ${TUNNEL_PYTHON}" >&2
        exit 1
    fi
    TUNNEL_PYTHON="$(command -v "$TUNNEL_PYTHON")"
    case "$TUNNEL_PYTHON" in
        /*) ;;
        *)  TUNNEL_PYTHON="$(cd "$(dirname "$TUNNEL_PYTHON")" && pwd)/$(basename "$TUNNEL_PYTHON")" ;;
    esac
fi
if ! "$TUNNEL_PYTHON" -c "import websockets" 2>/dev/null; then
    if [ -n "${COWORK_TUNNEL_PYTHON:-}" ]; then
        # Their interpreter, their call. Say what is wrong and change nothing.
        echo "[cowork-tunnel] WARNING: ${COWORK_TUNNEL_PYTHON} cannot import websockets." >&2
        echo "  The SSH tunnel needs it: ${COWORK_TUNNEL_PYTHON} -m pip install websockets" >&2
        echo "  The HTTP proxy does not, and still works." >&2
    else
        echo "[cowork-tunnel] Installing websockets (needed for the SSH tunnel)..."
        mkdir -p "$INSTALL_DIR"
        # A private venv first. `python3 -m venv` bootstraps its own pip through
        # ensurepip, so this works on hosts that ship no pip at all, needs no
        # --break-system-packages, and leaves system packages untouched. The
        # fallbacks matter where python3-venv is missing but pip is present; note
        # that pip older than 23 rejects --break-system-packages.
        if python3 -m venv "${INSTALL_DIR}/venv" >/dev/null 2>&1 &&
           "${INSTALL_DIR}/venv/bin/python3" -m pip install -q websockets >/dev/null 2>&1; then
            TUNNEL_PYTHON="${INSTALL_DIR}/venv/bin/python3"
            echo "[cowork-tunnel] Installed into ${INSTALL_DIR}/venv"
        elif python3 -m pip install -q --break-system-packages websockets 2>/dev/null; then
            :
        elif python3 -m pip install -q websockets 2>/dev/null; then
            :
        else
            # Not fatal: the HTTP proxy is standard-library only and still installs.
            echo "[cowork-tunnel] WARNING: could not install websockets." >&2
            echo "  The SSH tunnel needs it. The HTTP proxy does not, and still works." >&2
            echo "  Install python3-venv, or run: python3 -m pip install websockets" >&2
        fi
    fi
fi

# --- Download the proxy scripts ---------------------------------------------
# -f makes curl fail on 4xx/5xx. Without it a 404 page is written to disk as
# ws_proxy.py and the failure only shows up later as a broken SSH session.
mkdir -p "$INSTALL_DIR"

# Downloads land on a temp file first and are only moved into place once they
# look right. The trap covers the window in between, so an interrupted run
# leaves no half-written .ws_proxy.XXXXXX behind.
TMP_DOWNLOAD=""
cleanup() {
    [ -n "$TMP_DOWNLOAD" ] && rm -f "$TMP_DOWNLOAD"
    # An EXIT trap's last command becomes the script's exit status, so without
    # this a successful run exits 1 the moment TMP_DOWNLOAD is empty -- which
    # it always is once the download has been moved into place.
    return 0
}
trap cleanup EXIT INT TERM

download_script() {
    local name="$1"
    TMP_DOWNLOAD="$(mktemp "${INSTALL_DIR}/.${name}.XXXXXX")"

    if ! curl -fsSL "${REPO_RAW}/client/${name}" -o "$TMP_DOWNLOAD"; then
        echo "[cowork-tunnel] ERROR: failed to download ${name} from ${REPO_RAW}" >&2
        return 1
    fi

    if ! head -n 1 "$TMP_DOWNLOAD" | grep -q '^#!/usr/bin/env python3'; then
        echo "[cowork-tunnel] ERROR: downloaded ${name} does not look like the expected script." >&2
        echo "  First line: $(head -n 1 "$TMP_DOWNLOAD")" >&2
        return 1
    fi

    mv "$TMP_DOWNLOAD" "${INSTALL_DIR}/${name}"
    TMP_DOWNLOAD=""
    chmod +x "${INSTALL_DIR}/${name}"
}

if ! download_script "ws_proxy.py"; then
    exit 1
fi

if ! download_script "http_proxy.py"; then
    echo "[cowork-tunnel] WARNING: could not download http_proxy.py. HTTP proxy will not be available." >&2
fi

# --- Configure SSH ----------------------------------------------------------
# Replace any previous block rather than appending a second `Host *` stanza.
mkdir -p "$(dirname "$SSH_CONFIG")"
chmod 700 "$(dirname "$SSH_CONFIG")"
touch "$SSH_CONFIG"

if grep -qF "$MARKER_BEGIN" "$SSH_CONFIG"; then
    echo "[cowork-tunnel] Updating existing SSH config block..."
    sed -i "/${MARKER_BEGIN}/,/${MARKER_END}/d" "$SSH_CONFIG"
fi

cat >> "$SSH_CONFIG" << SSHEOF
${MARKER_BEGIN}
# SSH over WebSocket. Remove this block to disable the tunnel.
Host *
    ProxyCommand ${TUNNEL_PYTHON} ${INSTALL_DIR}/ws_proxy.py
    ServerAliveInterval 60
    ServerAliveCountMax 3
${MARKER_END}
SSHEOF

chmod 600 "$SSH_CONFIG"

echo "[cowork-tunnel] Ready. SSH will tunnel through ${COWORK_RELAY_URL}"
echo "[cowork-tunnel] Note: the 'Host *' block routes ALL ssh through the tunnel."
echo "[cowork-tunnel] Test with: ssh user@your-server"
if [ -f "${INSTALL_DIR}/http_proxy.py" ]; then
    echo "[cowork-tunnel] HTTP proxy also available:"
    echo "  python3 ${INSTALL_DIR}/http_proxy.py GET https://example.com"
fi
