#!/bin/sh
set -e

echo "=== ClawSec Tailscale Setup ==="

TS_VERSION="${TS_VERSION:-1.82.5}"
TS_HOSTNAME="${TS_HOSTNAME:-clawsec}"
BIN_DIR="$HOME/bin"
STATE_DIR="$HOME/.tailscale/state"
SOCK="$HOME/.tailscale/tailscaled.sock"
LOG="$HOME/.tailscale/tailscaled.log"

if [ -n "$TS_CLIENT_ID" ] && [ -n "$TS_CLIENT_SECRET" ]; then
    TS_AUTHKEY="tskey-client-${TS_CLIENT_ID}?secret=${TS_CLIENT_SECRET}"
    echo "Using Tailscale OAuth Client credentials."
elif [ -n "$TS_AUTHKEY" ]; then
    echo "Using Tailscale authkey."
else
    echo "No credentials set — skipping Tailscale setup."
    exit 0
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) TS_ARCH="amd64" ;;
    aarch64|arm64) TS_ARCH="arm64" ;;
    *) echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac
echo "Architecture: $ARCH ($TS_ARCH)"

INSTALL_TAILSCALE() {
    echo "Installing Tailscale $TS_VERSION..."
    TARBALL="tailscale_${TS_VERSION}_${TS_ARCH}.tgz"
    URL="https://pkgs.tailscale.com/stable/${TARBALL}"
    TMPDIR="$(mktemp -d)"
    curl -fsSL "$URL" -o "$TMPDIR/$TARBALL"
    tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"
    mkdir -p "$BIN_DIR"
    cp "$TMPDIR/tailscale_${TS_VERSION}_${TS_ARCH}/tailscale" "$BIN_DIR/tailscale"
    cp "$TMPDIR/tailscale_${TS_VERSION}_${TS_ARCH}/tailscaled" "$BIN_DIR/tailscaled"
    chmod +x "$BIN_DIR/tailscale" "$BIN_DIR/tailscaled"
    rm -rf "$TMPDIR"
    echo "Tailscale installed to $BIN_DIR"
}

if [ -x "$BIN_DIR/tailscale" ]; then
    INSTALLED_VERSION="$("$BIN_DIR/tailscale" version 2>/dev/null | head -1 || true)"
    if [ "$INSTALLED_VERSION" != "$TS_VERSION" ]; then
        INSTALL_TAILSCALE
    else
        echo "Tailscale $TS_VERSION already installed."
    fi
else
    INSTALL_TAILSCALE
fi

mkdir -p "$HOME/.tailscale/state"

if [ -S "$SOCK" ] && "$BIN_DIR/tailscale" --socket="$SOCK" status >/dev/null 2>&1; then
    echo "tailscaled already running."
else
    if [ -f "$HOME/.tailscale/tailscaled.pid" ]; then
        kill "$(cat "$HOME/.tailscale/tailscaled.pid")" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$SOCK"

    "$BIN_DIR/tailscaled" \
        --tun=userspace-networking \
        --statedir="$STATE_DIR" \
        --socket="$SOCK" \
        >"$LOG" 2>&1 &

    TAILSCALED_PID=$!
    echo "$TAILSCALED_PID" > "$HOME/.tailscale/tailscaled.pid"
    echo "tailscaled started (PID $TAILSCALED_PID)"

    WAIT=0
    while [ ! -S "$SOCK" ]; do
        sleep 1
        WAIT=$((WAIT + 1))
        if [ "$WAIT" -ge 30 ]; then
            echo "Error: tailscaled socket not ready after 30s"
            echo "Check logs: $LOG"
            exit 1
        fi
    done
    echo "tailscaled socket ready."
fi

BACKEND_STATE="$("$BIN_DIR/tailscale" --socket="$SOCK" status --json 2>/dev/null | grep -o '"BackendState":"[^"]*"' | cut -d'"' -f4 || true)"
if [ "$BACKEND_STATE" = "Running" ]; then
    echo "Tailscale already authenticated."
else
    echo "Authenticating with Tailscale..."
    "$BIN_DIR/tailscale" --socket="$SOCK" up \
        --authkey="$TS_AUTHKEY" \
        --hostname="$TS_HOSTNAME" \
        --accept-dns=false \
        ${TS_EXTRA_ARGS}
    echo "Tailscale authenticated."
fi

echo "Exposing ClawSec API via Tailscale Serve..."
"$BIN_DIR/tailscale" --socket="$SOCK" serve add 8080

echo ""
echo "=== Tailscale Setup Complete ==="
"$BIN_DIR/tailscale" --socket="$SOCK" status || true
echo ""
echo "ClawSec API available at: http://${TS_HOSTNAME}.<your-tailnet>.ts.net:8080"
