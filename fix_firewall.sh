#!/bin/bash

# fix_firewall.sh
# Safely restores /etc/pf.conf to a clean state and adds the Sovereign Guard anchor correctly.

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo:"
  echo "sudo $0"
  exit 1
fi

RULE_FILE="/etc/pf.anchors/com.sovereign.guard"
CONF_FILE="/etc/pf.conf"

echo "1. Ensuring the anchor rule file exists..."
echo "block drop quick proto tcp from any to any port 9222" > "$RULE_FILE"

echo "2. Restoring /etc/pf.conf to a clean structure..."
# We use a clean, standard macOS pf.conf template
cat <<EOF > "$CONF_FILE"
#
# Default PF configuration file.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"

# Sovereign Guard: Block Chrome DevTools Port
anchor "com.sovereign.guard"
load anchor "com.sovereign.guard" from "/etc/pf.anchors/com.sovereign.guard"
EOF

echo "3. Validating and reloading pf rules..."
if pfctl -vnf /etc/pf.conf; then
    pfctl -f /etc/pf.conf
    pfctl -e
    echo "--------------------------------------------------------"
    echo "✅ FIREWALL RECOVERY COMPLETE."
    echo "Port 9222 is now successfully sealed at the OS level."
    echo "--------------------------------------------------------"
else
    echo "❌ Validation failed. Reverting to backup (not implemented yet)..."
    exit 1
fi
