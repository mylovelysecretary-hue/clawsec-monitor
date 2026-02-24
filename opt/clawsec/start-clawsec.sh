#!/bin/sh
set -e

sh /opt/clawsec/setup-tailscale.sh

mkdir -p /var/run/tailscale
ln -sf "$HOME/.tailscale/tailscaled.sock" /var/run/tailscale/tailscaled.sock

exec python3 /app/clawsec-api.py start
