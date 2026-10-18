"""ubus JSON-RPC transport + login for the ZTE G5TS web UI.

No secrets are stored in this file: the router address and the admin password
are read from the environment.

    export G5TS_HOST=192.168.0.1
    export G5TS_PW='<admin password>'

`rl.SESS` is the live `ubus_rpc_session` obtained by `login()`.
"""
import hashlib
import json
import os
import ssl
import time
import urllib.request

ctx = ssl._create_unverified_context()

HOST = os.environ.get("G5TS_HOST", "192.168.0.1")
URL = "https://%s/ubus/?t=1" % HOST
ZERO = "0" * 32
PW = os.environ.get("G5TS_PW")


def sha(e):
    return hashlib.sha256(e.encode()).hexdigest().upper()


def _post(body, zmode, ztag, timeout=20, tries=4):
    h = {"Content-Type": "application/json", "Referer": "https://%s/" % HOST,
         "Z-Mode": zmode, "Z-Tag": ztag}
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(URL, data=body, headers=h, method="POST")
            return urllib.request.urlopen(req, context=ctx, timeout=timeout).read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.6)
    return "ERR %s" % last


def raw(session, obj, meth, args=None, zmode="0", ztag=None, timeout=20):
    body = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "call",
                        "params": [session, obj, meth, args or {}]}]).encode()
    return _post(body, zmode, ztag if ztag is not None else meth, timeout)


def login():
    if not PW:
        raise SystemExit("set G5TS_PW (admin password) in the environment")
    for _ in range(6):
        r = raw(ZERO, "zwrt_web", "web_login_info", {})
        try:
            sault = json.loads(r)[0]["result"][1]["zte_web_sault"]
        except Exception:  # noqa: BLE001
            time.sleep(1.0)
            continue
        for _ in range(6):
            r = raw(ZERO, "zwrt_web", "web_login", {"password": sha(sha(PW) + sault)})
            try:
                res = json.loads(r)[0]["result"][1]
                if str(res.get("result")) == "0":
                    return res["ubus_rpc_session"]
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1.0)
    raise SystemExit("login failed")


SESS = login()


def call(obj, meth, args=None, zmode="0", ztag=None, timeout=20):
    r = raw(SESS, obj, meth, args, zmode=zmode, ztag=ztag, timeout=timeout)
    try:
        return json.loads(r)
    except Exception:  # noqa: BLE001
        return r


def jcall(obj, meth, args=None, **kw):
    return json.dumps(call(obj, meth, args, **kw))[:500]
