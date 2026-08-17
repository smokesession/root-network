#!/usr/bin/env bash
# Root Browser launcher (Linux/macOS/VPS)
#
# 1. Starts the root client SOCKS5 proxy in the background.
# 2. Waits for the SOCKS port to actually be listening.
# 3. Launches Firefox with the Root Browser profile.
# 4. On browser exit, kills the background client process.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="${PROFILE_DIR:-"$SCRIPT_DIR/profile"}"
SOCKS_ADDR="${SOCKS_ADDR:-127.0.0.1:9050}"
SOCKS_HOST="${SOCKS_ADDR%%:*}"
SOCKS_PORT="${SOCKS_ADDR##*:}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"

ROOT_BIN="${ROOT_BIN:-}"
FIREFOX_BIN="${FIREFOX_BIN:-}"

CLIENT_PID=""

log()  { printf '[root-browser] %s\n' "$1"; }
err()  { printf '[root-browser] ERROR: %s\n' "$1" >&2; }

cleanup() {
    if [ -n "$CLIENT_PID" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        log "Shutting down root client (pid $CLIENT_PID)..."
        kill "$CLIENT_PID" 2>/dev/null
        wait "$CLIENT_PID" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# --- Parse optional flags -----------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --firefox-path) FIREFOX_BIN="$2"; shift 2 ;;
        --root-bin) ROOT_BIN="$2"; shift 2 ;;
        --socks-addr) SOCKS_ADDR="$2"; SOCKS_HOST="${SOCKS_ADDR%%:*}"; SOCKS_PORT="${SOCKS_ADDR##*:}"; shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

# --- Locate the root binary ----------------------------------------------
if [ -z "$ROOT_BIN" ]; then
    for candidate in \
        "$SCRIPT_DIR/../target/release/root" \
        "$SCRIPT_DIR/../target/debug/root" \
        "$(command -v root 2>/dev/null || true)"
    do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            ROOT_BIN="$candidate"
            break
        fi
    done
fi

if [ -z "$ROOT_BIN" ] || [ ! -x "$ROOT_BIN" ]; then
    err "Could not find the 'root' binary. Build it with 'cargo build --release' in the project root,"
    err "or pass --root-bin /path/to/root, or set ROOT_BIN=/path/to/root."
    exit 1
fi

# --- Locate Firefox --------------------------------------------------------
if [ -z "$FIREFOX_BIN" ]; then
    for candidate in firefox firefox-esr /Applications/Firefox.app/Contents/MacOS/firefox; do
        if command -v "$candidate" >/dev/null 2>&1; then
            FIREFOX_BIN="$(command -v "$candidate")"
            break
        elif [ -x "$candidate" ]; then
            FIREFOX_BIN="$candidate"
            break
        fi
    done
fi

if [ -z "$FIREFOX_BIN" ]; then
    err "Could not find a Firefox binary. Pass --firefox-path /path/to/firefox or set FIREFOX_BIN."
    exit 1
fi

if [ ! -d "$PROFILE_DIR" ]; then
    err "Profile directory not found: $PROFILE_DIR"
    exit 1
fi

# --- Start the client proxy -----------------------------------------------
log "Starting root client (SOCKS5 proxy) on $SOCKS_ADDR..."
"$ROOT_BIN" client --socks-addr "$SOCKS_ADDR" &
CLIENT_PID=$!

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    err "root client failed to start."
    exit 1
fi

# --- Wait for the SOCKS port to be listening -------------------------------
log "Waiting for SOCKS proxy at $SOCKS_ADDR to come up (timeout: ${WAIT_TIMEOUT}s)..."
elapsed=0
port_open=0
while [ "$elapsed" -lt "$WAIT_TIMEOUT" ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        err "root client process exited unexpectedly while waiting for the proxy port."
        exit 1
    fi
    if command -v nc >/dev/null 2>&1; then
        if nc -z "$SOCKS_HOST" "$SOCKS_PORT" 2>/dev/null; then
            port_open=1
            break
        fi
    else
        # Fallback: try /dev/tcp (bash builtin)
        if (exec 3<>"/dev/tcp/$SOCKS_HOST/$SOCKS_PORT") 2>/dev/null; then
            exec 3>&- 3<&-
            port_open=1
            break
        fi
    fi
    sleep 0.5
    elapsed=$((elapsed + 1))
done

if [ "$port_open" -ne 1 ]; then
    err "Timed out waiting for SOCKS proxy to listen on $SOCKS_ADDR."
    exit 1
fi
log "SOCKS proxy is up."

# --- Launch Firefox ---------------------------------------------------------
log "Launching Firefox with the Root Browser profile..."
log "Ready. Close the browser window to shut everything down."
"$FIREFOX_BIN" -profile "$PROFILE_DIR" -no-remote

log "Firefox exited."
# cleanup runs via trap on EXIT
