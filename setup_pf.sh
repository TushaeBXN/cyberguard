#!/bin/bash
# setup_pf.sh — One-time setup to enable CyberGuard AI auto-blocking via pf
#
# Run once with: sudo bash setup_pf.sh
# After this, any IP caught by the honeypot is blocked automatically.

set -e

PF_TABLE="cyberguard_block"
BLOCKLIST="/etc/cyberguard_blocklist"
PF_CONF="/etc/pf.conf"
SUDOERS_FILE="/etc/sudoers.d/cyberguard"
USER="${SUDO_USER:-$(logname)}"

echo "=== CyberGuard AI — pf firewall setup ==="
echo "User: $USER"
echo

# 1. Create the persistent block file pf loads from
if [ ! -f "$BLOCKLIST" ]; then
    touch "$BLOCKLIST"
    echo "Created $BLOCKLIST"
else
    echo "$BLOCKLIST already exists"
fi

# 2. Add pf table + block rule to pf.conf if not already present
if ! grep -q "$PF_TABLE" "$PF_CONF" 2>/dev/null; then
    # Prepend the table and block rule before any existing rules
    TMP=$(mktemp)
    echo "# CyberGuard AI — auto-block table (added by setup_pf.sh)" > "$TMP"
    echo "table <$PF_TABLE> persist file \"$BLOCKLIST\"" >> "$TMP"
    echo "block drop in quick from <$PF_TABLE> to any" >> "$TMP"
    echo "" >> "$TMP"
    cat "$PF_CONF" >> "$TMP"
    cp "$TMP" "$PF_CONF"
    rm "$TMP"
    echo "Added table + block rule to $PF_CONF"
else
    echo "pf table already in $PF_CONF"
fi

# 3. Reload pf and enable it
pfctl -f "$PF_CONF"
pfctl -e 2>/dev/null || true
echo "pf reloaded and enabled"

# 4. Add scoped sudoers rule so CyberGuard can call pfctl without a password
#    Only these exact commands are allowed — not all of pfctl.
cat > "$SUDOERS_FILE" << EOF
# CyberGuard AI — allow pfctl table operations without password prompt
$USER ALL=(root) NOPASSWD: /sbin/pfctl -t $PF_TABLE -T add *
$USER ALL=(root) NOPASSWD: /sbin/pfctl -t $PF_TABLE -T delete *
$USER ALL=(root) NOPASSWD: /sbin/pfctl -t $PF_TABLE -T show
EOF
chmod 440 "$SUDOERS_FILE"
echo "Sudoers rule written to $SUDOERS_FILE"

echo
echo "=== Setup complete ==="
echo "CyberGuard AI will now block attacker IPs automatically via pf."
echo "Blocked IPs persist across reboots via $BLOCKLIST"
echo "To see blocked IPs:  sudo pfctl -t $PF_TABLE -T show"
echo "To remove an IP:     sudo pfctl -t $PF_TABLE -T delete <IP>"
echo "Or use the CyberGuard UI — /firewall/blocked endpoint"
