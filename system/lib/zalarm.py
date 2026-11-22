#!/usr/bin/env python3
"""ZENOS alerting (PoC).

severity "red": a full-screen flashing siren that rings until a person ACKNOWLEDGEs it (zenos_siren), PLUS a
fan-out to every pre-registered senior's device (dispatch). Red is meant to be impossible to ignore and to
reach the chain of command, not just the one machine.
severity "low": on-screen notice only.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zconf
Z = zconf.data()
STATE = os.path.join(Z, "redalert.json")
PID = os.path.join(Z, "redalert.pid")
RECIPIENTS = os.path.join(Z, "alert-recipients.json")
INBOX = os.path.join(Z, "alerts-outbox")          # per-recipient fan-out (reaches their device via the grid)
LEDGER = os.path.join(Z, "ledger.jsonl")
SIREN = os.path.join(zconf.SBIN, "zenos_siren.py")


def as_desk_user(fn):
    """Run fn() with the desk user's rights. Z is that user's own folder: when a root service raises an alert, the files
    there are written by a child that has become the user, so a link the user planted (to a root file) or a recipient
    name that climbs out of the folder can only reach what the user could write anyway."""
    if os.geteuid() != 0:
        return fn()
    import pwd
    try:
        pw = pwd.getpwnam(zconf.user())
    except KeyError:
        return None
    if pw.pw_uid == 0:
        return None
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.setgroups([]); os.setgid(pw.pw_gid); os.setuid(pw.pw_uid)
            fn(); code = 0
        except BaseException:
            pass
        finally:
            os._exit(code)
    t = time.time()
    while time.time() - t < 10:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            return True
        time.sleep(0.05)
    try:
        os.kill(pid, 9); os.waitpid(pid, 0)
    except OSError:
        pass
    return None


SAFE_ID = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except Exception:
        return False


def _ensure_siren(text):
    def write():
        os.makedirs(Z, exist_ok=True)
        with open(STATE, "w") as f:
            json.dump({"text": text, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, f)
    as_desk_user(write)
    try:
        if os.path.exists(PID) and _alive(int(open(PID).read().strip())):
            return                                   # already ringing; message refreshed via STATE
    except Exception:
        pass
    env = zconf.pulse_env()
    env.setdefault("DISPLAY", ":0" if not os.path.exists("/tmp/.X11-unix/X1") else ":1")
    if os.geteuid() == 0:     # a root service rings the siren on the desktop user's screen
        cmd = ["runuser", "-u", zconf.user(), "--", "env", "DISPLAY=" + env["DISPLAY"],
               "PULSE_SERVER=" + env.get("PULSE_SERVER", ""), "HOME=" + zconf.home(), "python3", "-I", SIREN]
    else:
        cmd = ["python3", "-I", SIREN]
    try:
        subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _recipients():
    try:
        return json.load(open(RECIPIENTS))
    except Exception:
        return []


def _msg_port():
    """the desk account's messenger port (ports.env), but only while the program listening there runs as the desk
    user: the alert and the messenger's key never go to another account that took the port"""
    import sys
    port = 8096
    try:
        fd = os.open(os.path.join(Z, "msg", "ports.env"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            for line in os.read(fd, 4096).decode("utf-8", "replace").splitlines():
                a, _, p = line.strip().partition("=")
                if a == "zenos" and p.isdigit() and 1024 <= int(p) <= 65535:
                    port = int(p)
        finally:
            os.close(fd)
    except OSError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    for d in ("/usr/share/zenos/bin", os.path.join(here, "..", "..", "core", "bin")):
        if os.path.isfile(os.path.join(d, "zenos_portcheck.py")) and d not in sys.path:
            sys.path.append(d)
    try:
        import zenos_portcheck
        u = zenos_portcheck.listeners(port)
    except Exception:
        return None
    return port if u and all(x == _desk_uid() for x in u) else None


def _msg_key():
    """The messenger's local key (it answers only callers that show it). The file sits in the desk user's folder, so it
    is opened without following a link and used only if that user owns it: a planted link to a root file gives nothing."""
    import stat
    try:
        fd = os.open(os.path.join(Z, "msg", "store", "zenos", "local.key"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != _desk_uid() or st.st_size > 128:
            return ""
        k = os.read(fd, 128).decode("ascii", "replace").strip()
        return k if k and all(c.isalnum() or c in "-_" for c in k) else ""
    finally:
        os.close(fd)


def _desk_uid():
    import pwd
    try:
        return pwd.getpwnam(zconf.user()).pw_uid
    except Exception:
        return os.getuid()


def dispatch(title, text, reasons):
    """Fan the alert out to every pre-registered senior's device (PoC: per-recipient outbox + ledger)."""
    sent = []
    recs = [r for r in _recipients() if isinstance(r, dict) and SAFE_ID.match(str(r.get("id", "")))]

    def write_outbox():
        for r in recs:
            try:
                d = os.path.join(INBOX, r["id"]); os.makedirs(d, exist_ok=True)
                fn = os.path.join(d, time.strftime("%Y%m%d-%H%M%S") + ".json")
                with open(fn, "w") as f:
                    json.dump({"to": r, "title": title, "text": text, "reasons": reasons,
                               "severity": "red", "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, f, ensure_ascii=False)
            except Exception:
                pass
    if recs and as_desk_user(write_outbox):
        sent += [r["id"] for r in recs]
    key = _msg_key()
    port = _msg_port()
    try:
        import urllib.request as _u
        if not port:
            raise OSError("the desk messenger is not the one listening")
        req = _u.Request(f"http://127.0.0.1:{port}/api/channel-send",
                         data=__import__("json").dumps({"ch": "alerts", "text": "RED ALERT: " + text, "level": 4}).encode(),
                         headers={"Content-Type": "application/json", "X-Zenos-Local": key})
        _u.urlopen(req, timeout=4)              # post into #alerts -> fans out to seniors' PWAs
    except Exception:
        pass
    try:                                        # Web Push to the owner's linked phone(s), even when the app is closed
        import urllib.request as _u
        if not port:
            raise OSError("the desk messenger is not the one listening")
        req = _u.Request(f"http://127.0.0.1:{port}/api/push/alert",
                         data=__import__("json").dumps({"title": "ZENOS RED ALERT: " + str(title)[:60], "body": str(text)[:300]}).encode(),
                         headers={"Content-Type": "application/json", "X-Zenos-Local": key})
        r = __import__("json").loads(_u.urlopen(req, timeout=8).read() or b"{}")
        if r.get("sent"):
            sent.append("owner-phone-push")
    except Exception:
        pass
    def write_ledger():
        import zledger
        dev = __import__("hashlib").sha256(b"node-A").hexdigest()[:16]
        zledger.append(LEDGER, "red-dispatch", "alarm", dev, recipients=sent, reasons=reasons, text=text)
    try:
        as_desk_user(write_ledger)
    except Exception:
        pass
    return sent


def _notify(title, text, urgent):
    for disp in (os.environ.get("DISPLAY"), ":1", ":0"):
        if not disp:
            continue
        try:
            subprocess.run(["notify-send"] + (["-u", "critical"] if urgent else ["-u", "normal"]) +
                           [title, text], env={**os.environ, "DISPLAY": disp}, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            break
        except Exception:
            continue


def ack():
    for f in (STATE, PID):
        try:
            os.remove(f)
        except Exception:
            pass


def raise_alert(severity, title, text, reasons=None):
    reasons = reasons or []
    _notify(title, text, urgent=(severity == "red"))
    if severity == "red":
        _ensure_siren(text)
        dispatch(title, text, reasons)
    return severity


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "ack":
        ack(); print("acknowledged")
    else:
        raise_alert("red", "ZENOS RED ALERT", sys.argv[1] if len(sys.argv) > 1 else "test", [])
