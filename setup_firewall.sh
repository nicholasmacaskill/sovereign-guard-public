#!/bin/bash

# setup_firewall.sh
# Seals TCP port 9222 (Chrome DevTools Protocol) using pf.
# This ensures that even if a process is launched with the debug flag,
# it cannot be reached from the network or other local processes.

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo:"
  echo "sudo $0"
  exit 1
fi

RULE_FILE="/etc/pf.anchors/com.sovereign.guard"
CONF_FILE="/etc/pf.conf"

echo "Creating Sovereign Guard firewall anchor..."
echo "block drop quick proto tcp from any to any port 9222" > "$RULE_FILE"

# Check if anchor is already in pf.conf
if ! grep -q "com.sovereign.guard" "$CONF_FILE"; then
    echo "Registering anchor in /etc/pf.conf..."
    # Add anchor and load rule
    # Note: We append to the end of the file or after existing anchors
    sed -i '' '/anchor "com.apple\/\*"/a \
anchor "com.sovereign.guard" \
load anchor "com.sovereign.guard" from "/etc/pf.anchors/com.sovereign.guard"' "$CONF_FILE"
fi

echo "Reloading pf rules..."
pfctl -f /etc/pf.conf
pfctl -e

echo "--------------------------------------------------------"
echo "✅ PORT 9222 SEALED."
echo "The Chrome DevTools Protocol is now blocked at the OS level."
echo "--------------------------------------------------------"
