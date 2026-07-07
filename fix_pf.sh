#!/bin/bash
# fix_pf.sh — Fix pf.conf rule ordering (block rule must come after anchors)
set -e

PF_CONF="/etc/pf.conf"

echo "=== Fixing pf.conf rule ordering ==="

# Write the corrected pf.conf: table at top, block rule at the bottom (after anchors)
cat > "$PF_CONF" << 'PFEOF'
# CyberGuard AI — auto-block table
table <cyberguard_block> persist file "/etc/cyberguard_blocklist"

#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and disabling
# PF via -E and -X as documented in pfctl(8).  That will ensure that PF
# is disabled only when the last enable reference is released.
#
# Care must be taken to ensure that the main ruleset does not get flushed,
# as the nested anchors rely on the anchor point defined here. In addition,
# to the anchors loaded by this file, some system services would dynamically
# insert anchors into the main ruleset. These anchors will be added only when
# the system service is used and would removed on termination of the service.
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

# CyberGuard AI — block rule (after normalization/translation anchors, as required)
block drop in quick from <cyberguard_block> to any
PFEOF

echo "pf.conf written"

# Reload and enable
pfctl -f "$PF_CONF" && echo "pf rules loaded: OK" || { echo "ERROR: pfctl -f failed"; exit 1; }
pfctl -e 2>/dev/null || true
echo "pf enabled"

# Add the two real attackers that already hit the honeypot
pfctl -t cyberguard_block -T add 221.212.228.238 && echo "Blocked: 221.212.228.238 (SSH scanner)" || true
pfctl -t cyberguard_block -T add 4.193.139.29   && echo "Blocked: 4.193.139.29 (JBoss scanner)"  || true

echo
echo "=== Done ==="
echo "Blocked IPs:"
pfctl -t cyberguard_block -T show
echo
echo "Future honeypot hits will be blocked automatically."
