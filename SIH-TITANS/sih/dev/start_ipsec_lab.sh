#!/bin/bash
# Optional Linux IPsec Lab Starter (For Local Traffic Generation)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[+] Starting IPsec lab from $SCRIPT_DIR..."

# Recreate namespaces and veth network
"$SCRIPT_DIR/setup_ipsec_lab.sh" || exit 1

# Start LEFT and RIGHT strongSwan daemons
sudo env STRONGSWAN_CONF=/etc/strongswan-left.conf \
    ip netns exec ipsec-left /usr/sbin/charon-systemd &

sudo env STRONGSWAN_CONF=/etc/strongswan-right.conf \
    ip netns exec ipsec-right /usr/sbin/charon-systemd &

sleep 2

# Load configurations and credentials
sudo swanctl --uri unix:///run/charon-left.vici --load-conns
sudo swanctl --uri unix:///run/charon-left.vici --load-creds

sudo swanctl --uri unix:///run/charon-right.vici --load-conns
sudo swanctl --uri unix:///run/charon-right.vici --load-creds

echo "[+] IPsec lab and strongSwan ready."
echo "[+] Establishing tunnel..."

sudo swanctl --uri unix:///run/charon-left.vici \
    --initiate --child tunnel

echo "[+] IPsec tunnel setup finished."
