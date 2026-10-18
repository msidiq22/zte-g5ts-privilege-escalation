#!/bin/sh
# zte-g5ts-privilege-escalation / verify.sh
# Run on the ZTE G5TS to enumerate every artifact / side-effect left by the PoC.
# Works as `nobody`; some lines need root (marked) to read.

echo "###################### 1. MODIFIED / LEFT FILES ######################"
for f in \
    /usr/share/miniupnpd/firewall.include \
    /etc/firewall.user \
    /etc_rw/bbroot \
    /usr/share/fw3/helpers.conf \
    /usr/share/fw3/zzz /usr/share/fw3/zzz2 ; do
    if [ -e "$f" ]; then ls -l "$f"; else echo "absent: $f"; fi
done

echo
echo "--- payload marker inside the include? (expect EMPTY after revert) ---"
grep -n 'poc payload\|MINIUPNPD_INCLUDE_RAN\|zpwn_root' /usr/share/miniupnpd/firewall.include 2>/dev/null || echo "  clean"

echo
echo "--- '# wrtest' in helpers.conf? (expect EMPTY after revert) ---"
grep -n '# wrtest' /usr/share/fw3/helpers.conf 2>/dev/null || echo "  clean"

echo
echo "###################### 2. /tmp (volatile) ######################"
ls -l /tmp/rc.sh /tmp/back_parameter /tmp/zpwn_root /tmp/root_id \
      /tmp/shadow_root /tmp/miniupnpd.inc.bak /tmp/bbt /tmp/etc.tgz 2>/dev/null \
      || echo "  none present"

echo
echo "###################### 3. zte_dm self-update leftovers ######################"
ls -l /etc_rw/ztembb/dm/ 2>/dev/null
echo "selfupconfig.dat:"; cat /etc_rw/ztembb/dm/selfupconfig.dat 2>/dev/null
echo "(SELFUP_FLAG should be 0)"

echo
echo "###################### 4. LISTENERS / STRAY PROCS ######################"
netstat -ltnp 2>/dev/null | grep -E '31337|15555|8088' || echo "  no PoC listeners"
echo "--- tcpsvd/nc/logread ---"
ps w 2>/dev/null | grep -E 'tcpsvd|nc |logread' | grep -v grep || echo "  none"

echo
echo "###################### 5. uci / RPC SIDE-EFFECTS ######################"
echo "--- firewall-related zwrt_router values ---"
uci show zwrt_router 2>/dev/null | grep -Ei \
  'alg_sip|dmz|portforward_enable|portmapping_enable|mac_ip_bond|guest_access_restrict|remote_web|wan_ping|enable_upnp' \
  || echo "  (none matched)"
echo "--- test domain filter (ztest-pwn.example) ---"
uci show zwrt_router 2>/dev/null | grep -i 'ztest-pwn' || echo "  clean"
echo "--- test port mapping (18081 / 18080 / ztest) ---"
uci show firewall 2>/dev/null | grep -iE '18081|18080|ztest' || echo "  clean"
echo "--- UPnP state ---"
uci show upnpd 2>/dev/null | grep -i enable || true

echo
echo "###################### 6. DM BACKUPS ON DEVICE ######################"
ls -l /tmp/miniupnpd.inc.bak 2>/dev/null || echo "  (no on-device backup; use restore/ from the PoC)"

echo
echo "Tip: restore with  'sh /tmp/revert.sh'  (root), then re-run this script."
