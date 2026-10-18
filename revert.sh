#!/bin/sh
# zte-g5ts-privilege-escalation / revert.sh
# Run on the ZTE G5TS. Prefer running as ROOT (via the :31337 shell or serial):
#   sh /tmp/revert.sh
# It also works as `nobody` for the file/process parts, but ownership will be
# nobody instead of root, so re-run `chown root:root` afterwards if needed.
#
# Restores the two files that were modified and removes every PoC artifact.

echo "[1/7] restoring /usr/share/miniupnpd/firewall.include"
rm -f /usr/share/miniupnpd/firewall.include
cat > /usr/share/miniupnpd/firewall.include <<'MINIUPNPD_EOF'
#!/bin/sh
# miniupnpd integration for firewall3

IPTABLES="/usr/sbin/iptables"
IP6TABLES="/usr/sbin/ip6tables"
IPTARGS="-w 1"

$IPTABLES -t filter -N MINIUPNPD 2>/dev/null
$IPTABLES -t nat -N MINIUPNPD 2>/dev/null
$IPTABLES -t nat -N MINIUPNPD-POSTROUTING 2>/dev/null

[ -x $IP6TABLES ] && $IP6TABLES -t filter -N MINIUPNPD 2>/dev/null

. /lib/functions/network.sh

# helper to insert in chain as penultimate
iptables_prepend_rule() {
	local iptables="$1"
	local table="$2"
	local chain="$3"
	local target="$4"

	$iptables "$IPTARGS" -t "$table" -I "$chain" $($iptables "$IPTARGS" -t "$table" --line-numbers -nL "$chain" | \
		sed -ne '$s/[^0-9].*//p') -j "$target"
}

ADDED=0

add_extzone_rules() {
    local ext_zone="$1"

    [ -z "$ext_zone" ] && return

    # IPv4 - due to NAT, need to add both to nat and filter table
    # need to insert as penultimate rule for input & forward & postrouting since final rule might be a fw3 REJECT
    iptables_prepend_rule "$IPTABLES" filter "zone_${ext_zone}_input" MINIUPNPD
    iptables_prepend_rule "$IPTABLES" filter "zone_${ext_zone}_forward" MINIUPNPD
    $IPTABLES -t nat -A "zone_${ext_zone}_prerouting"  -j MINIUPNPD
    iptables_prepend_rule "$IPTABLES" nat "zone_${ext_zone}_postrouting" MINIUPNPD-POSTROUTING

    # IPv6 if available - filter only
    [ -x $IP6TABLES ] && {
	iptables_prepend_rule "$IP6TABLES" filter "zone_${ext_zone}_input" MINIUPNPD
	iptables_prepend_rule "$IP6TABLES" filter "zone_${ext_zone}_forward" MINIUPNPD
    }
    ADDED=$(($ADDED + 1))
}

# By default, user configuration is king.

for ext_iface in $(uci -q get upnpd.config.external_iface); do
    add_extzone_rules $(fw3 -q network "$ext_iface")
done

add_extzone_rules $(uci -q get upnpd.config.external_zone)

[ "$ADDED" -ne 0 ] && exit 0

# If really nothing is available, resort to network_find_wan{,6} and
# assume external interfaces all have same firewall zone.

# (This heuristic may fail horribly, in case of e.g. multihoming, so
# please set external_zone in that case!)

network_find_wan wan_iface
network_find_wan6 wan6_iface

for ext_iface in $wan_iface $wan6_iface; do
    # fw3 -q network fails on sub-interfaces => map to device first
    network_get_device ext_device $ext_iface
    add_extzone_rules $(fw3 -q device "$ext_device")
done
MINIUPNPD_EOF
chmod 755 /usr/share/miniupnpd/firewall.include
chown root:root /usr/share/miniupnpd/firewall.include 2>/dev/null

echo "[2/7] restoring /etc/firewall.user"
rm -f /etc/firewall.user
cat > /etc/firewall.user <<'FIREWALL_USER_EOF'
# This file is interpreted as shell script.
# Put your custom iptables rules here, they will
# be executed with each firewall (re-)start.

# Internal uci firewall chains are flushed and recreated on reload, so
# put custom rules into the root chains e.g. INPUT or FORWARD or into the
# special user chains, e.g. input_wan_rule or postrouting_lan_rule.
FIREWALL_USER_EOF
chmod 644 /etc/firewall.user
chown root:root /etc/firewall.user 2>/dev/null

echo "[3/7] removing filesystem artifacts"
rm -f /etc_rw/bbroot
rm -f /usr/share/fw3/zzz /usr/share/fw3/zzz2
rm -f /tmp/rc.sh /tmp/back_parameter /tmp/zpwn_root /tmp/root_id \
      /tmp/shadow_root /tmp/miniupnpd.inc.bak /tmp/bbt /tmp/etc.tgz /tmp/bbroot
rm -f /tmp/zpwn /tmp/zpwn2 /tmp/zpwn3

echo "[4/7] removing '# wrtest' marker from helpers.conf"
if [ -f /usr/share/fw3/helpers.conf ]; then
    sed -i '/# wrtest/d' /usr/share/fw3/helpers.conf 2>/dev/null || true
fi

echo "[5/7] disarming zte_dm self-update leftovers"
if [ -f /etc_rw/ztembb/dm/selfupconfig.dat ]; then
    sed -i 's/^SELFUP_FLAG=.*/SELFUP_FLAG=0/' /etc_rw/ztembb/dm/selfupconfig.dat 2>/dev/null || true
fi
rm -f /etc_rw/ztembb/dm/zte_dm_0

echo "[6/7] stopping listeners (31337 / 15555 / 8088) and stray nc"
kill $(pidof tcpsvd) 2>/dev/null || true
kill $(pidof nc) 2>/dev/null || true

echo "[7/7] reloading firewall with the pristine include"
/etc/init.d/firewall reload >/dev/null 2>&1 || true

echo
echo "DONE. Files restored:"
ls -l /usr/share/miniupnpd/firewall.include /etc/firewall.user 2>/dev/null
echo
echo "NOTE: this script does NOT revert the uci/RPC side-effects. See"
echo "      verify.sh and docs/WRITEUP.md section 7.3 (UPnP, DMZ, remote ACL,"
echo "      ztest-pwn.example domain filter, 18081 port mapping)."
