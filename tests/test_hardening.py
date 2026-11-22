"""Kernel hardening and outside visibility (0.1.2): the sysctl and module settings the package installs, the restart
window for kernel fixes, and what the audit node learns from a PC's signed status (system/sbin/zenos_auditship.py,
zenos_auditnode.py, zenos_restartwindow.py). The audit node's chain check runs zenos-decide: cd formal && lake build."""
import base64, hashlib, json, os, sys, tempfile, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../system/sbin"))
sys.path.insert(0, os.path.join(HERE, "../system/lib"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import zledger
import zenos_auditnode as an
import zenos_auditship as ship
import zenos_restartwindow as rw


def read(p):
    with open(p) as f:
        return f.read()


class KernelSettings(unittest.TestCase):
    def test_sysctl(self):
        kv = {}
        for line in read(os.path.join(HERE, "../system/sysctl.d/60-zenos-hardening.conf")).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            self.assertTrue(k.strip() and v.strip(), line)
            self.assertNotIn(k.strip(), kv, "set twice: " + k)
            kv[k.strip()] = v.strip()
        self.assertEqual(kv["net.mptcp.enabled"], "0")
        self.assertEqual(kv["kernel.io_uring_disabled"], "2")
        self.assertEqual(kv["kernel.unprivileged_bpf_disabled"], "1")
        self.assertEqual(kv["kernel.kptr_restrict"], "1")       # 2 would hide symbols from the root sentinel too

    def test_lockdown(self):
        g = read(os.path.join(HERE, "../system/grub.d/zenos-hardening.cfg"))
        line = [l for l in g.splitlines() if l.startswith("GRUB_CMDLINE_LINUX_DEFAULT=")]
        self.assertEqual(len(line), 1)
        self.assertIn("$GRUB_CMDLINE_LINUX_DEFAULT ", line[0])      # adds to the existing line, never replaces it
        self.assertIn("lockdown=integrity", line[0])
        self.assertIn("lockdown=integrity", read(os.path.join(HERE, "../packaging/iso/build-iso.sh")))

    def test_modules(self):
        mods = []
        for line in read(os.path.join(HERE, "../system/modprobe.d/zenos-blacklist.conf")).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.split()
            self.assertEqual((w[0], w[2], len(w)), ("install", "/bin/false", 3), line)
            mods.append(w[1])
        for m in ("dccp", "sctp", "rds", "tipc", "firewire-ohci"):
            self.assertIn(m, mods)
        for needed in ("squashfs", "overlay", "isofs", "vfat", "exfat", "ext4", "udf", "usb_storage", "dm_crypt", "nf_tables", "bluetooth"):
            self.assertNotIn(needed, mods, needed + " is needed by the live image, USB drives, encryption or the firewall")


class RestartWindow(unittest.TestCase):
    def test_decide(self):
        now = time.time()
        user = lambda idle, since: ("1", "user", idle, since)
        self.assertEqual(rw.decide("no-session", False, [], now, 3)[0], False)
        self.assertEqual(rw.decide("off", True, [], now, 3)[0], False)
        self.assertEqual(rw.decide("no-session", True, [("c1", "greeter", False, 0)], now, 14)[0], True)
        self.assertEqual(rw.decide("no-session", True, [user(True, now - 7200)], now, 3)[0], False)
        self.assertEqual(rw.decide("idle", True, [user(True, now - 7200)], now, 3)[0], True)
        self.assertEqual(rw.decide("idle", True, [user(True, now - 600)], now, 3)[0], False)     # idle, but not an hour
        self.assertEqual(rw.decide("idle", True, [user(True, now - 7200)], now, 14)[0], False)   # not at night
        self.assertEqual(rw.decide("idle", True, [user(False, 0)], now, 3)[0], False)

    def test_fix_waiting(self):
        with tempfile.TemporaryDirectory() as d:
            flag = os.path.join(d, "reboot-required")
            self.assertFalse(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])
            self.assertTrue(rw.fix_waiting("6.12.112+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])
            self.assertFalse(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.99+deb13-amd64", flag)[0])   # 113 > 99, numerically
            open(flag, "w").close()
            self.assertTrue(rw.fix_waiting("6.12.113+deb13-amd64", "6.12.113+deb13-amd64", flag)[0])

    def test_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "policy.conf")
            rw.POLICY = p
            self.assertEqual(rw.policy(), "no-session")
            with open(p, "w") as f:
                f.write("terminal = allowed\nkernel_restart = idle   # at night\n")
            self.assertEqual(rw.policy(), "idle")
            with open(p, "w") as f:
                f.write("kernel_restart = always\n")
            self.assertEqual(rw.policy(), "no-session")         # an unknown value keeps the default


class AuditStatus(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.node = an.Node(self.d.name + "/node")
        self.key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.node.enroll("pc-1", pub)
        self.ledger = self.d.name + "/l.jsonl"
        zledger.append(self.ledger, "boot", "root", "pc-1")

    def tearDown(self):
        self.d.cleanup()

    def records(self):
        with open(self.ledger) as f:
            return [json.loads(l) for l in f if l.strip()]

    def alerts(self):
        p = os.path.join(self.d.name, "node", "alerts.jsonl")
        with open(p) as f:
            return [json.loads(l)["event"] for l in f if l.strip()]

    def send(self, st, tamper=False):
        b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": self.records(), "status": st}
        ship.sign(self.key, b)
        if tamper:
            b["status"] = dict(st, services={k: "active" for k in st["services"]})
        return self.node.accept(b)

    def st(self, **kw):
        AuditStatus.clock = getattr(AuditStatus, "clock", int(time.time()) - 100) + 1    # each status newer
        s = {"t": AuditStatus.clock, "kernel": "6.12.113+deb13-amd64", "kernel_newest": "6.12.113+deb13-amd64", "reboot_required": False,
             "services": {k: "active" for k in ship.WATCHED}}
        s.update(kw)
        return s

    def test_status_alerts(self):
        self.assertEqual(self.send(self.st())[0], 200)
        self.assertNotIn("service-down", self.alerts())
        down = self.st(services=dict(self.st()["services"], **{"zenos-guardd": "inactive"}))
        self.assertEqual(self.send(down)[0], 200)
        self.assertEqual(self.alerts().count("service-down"), 1)
        self.send(down)
        self.assertEqual(self.alerts().count("service-down"), 1)            # once, not on every heartbeat
        self.send(self.st())
        self.assertIn("service-back", self.alerts())
        self.send(self.st(kernel="6.12.112+deb13-amd64"))
        self.assertIn("kernel-fix-not-applied", self.alerts())
        self.send(self.st())
        self.assertIn("kernel-fix-applied", self.alerts())

    def test_forged_status_is_flagged_and_the_batch_still_counts(self):
        down = self.st(services=dict(self.st()["services"], **{"zenos-keyd": "failed"}))
        code, ans = self.send(down, tamper=True)
        self.assertEqual(code, 200)                                           # the ledger itself was signed correctly
        self.assertIn("bad-status-signature", self.alerts())
        self.assertNotIn("service-down", self.alerts())

    def test_batch_without_status_still_accepted(self):
        b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": self.records()}
        ship.sign(self.key, b)
        self.assertNotIn("status_sig", b)
        self.assertEqual(self.node.accept(b)[0], 200)

    def test_a_record_that_is_not_an_object_is_refused(self):
        self.assertEqual(self.send(self.st())[0], 200)
        for bad in ([1], ["x"], [None], [[1]]):
            b = {"machine": "pc-1", "chain": "guard", "from": 0, "records": bad}
            ship.sign(self.key, b)
            self.assertEqual(self.node.accept(b)[0], 400, bad)                 # an answer, not a crash

    def test_silence_in_seconds(self):
        self.send(self.st())
        seen = os.path.join(self.d.name, "node", "machines", "pc-1.seen")
        with open(seen, "w") as f:
            f.write(str(time.time() - 120))
        self.node.check_silence(90)
        self.assertIn("machine-silent", self.alerts())



class KeydHolders(unittest.TestCase):
    """keyd records every process holding the client end of the connection, not just the one that connected"""
    def test_a_socket_handed_on_is_still_held(self):
        import socket as S, importlib
        with tempfile.TemporaryDirectory() as d:
            os.environ["ZENOS_OPEN_HOLDERS"] = os.path.join(d, "h.json")
            import zenos_keyd as K
            importlib.reload(K)
            srv = S.socket(S.AF_UNIX); srv.bind(os.path.join(d, "s")); srv.listen(1)
            cli = S.socket(S.AF_UNIX); cli.connect(os.path.join(d, "s"))
            conn, _ = srv.accept()
            dead = 999999                                               # the connector has gone
            ok = K.hold(dead, os.getuid(), 4, os.fstat(conn.fileno()).st_ino)
            held = [h["pid"] for h in json.load(open(os.environ["ZENOS_OPEN_HOLDERS"]))] if ok else []
            self.assertIn(os.getpid(), held)                            # this process holds the client end
            self.assertFalse(K.hold(dead, os.getuid(), 4, None))        # nobody alive: no plaintext
            self.assertTrue(K.hold(0, os.getuid(), 3, None))            # below L4 nothing is held
            for x in (cli, conn, srv):
                x.close()
            del os.environ["ZENOS_OPEN_HOLDERS"]


class AuditNodeIntake(unittest.TestCase):
    """only an enrolled machine can make the audit node read a batch into memory, and the batch must be that
    machine's; anyone else is turned away from the headers alone"""
    def test_gate(self):
        with tempfile.TemporaryDirectory() as d:
            node = an.Node(os.path.join(d, "node"))
            k = Ed25519PrivateKey.generate()
            pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,
                                                               serialization.PublicFormat.Raw)).decode()
            node.enroll("pc-1", pub)
            g = lambda h: an.post_gate(node, h)[0]
            self.assertEqual(g({"Content-Length": "100"}), 403)                              # no machine named
            self.assertEqual(g({"X-Zenos-Machine": "pc-9", "Content-Length": "100"}), 403)   # not enrolled
            self.assertEqual(g({"X-Zenos-Machine": "../x", "Content-Length": "100"}), 403)
            self.assertEqual(g({"X-Zenos-Machine": "pc-1", "Content-Length": str(an.MAX_BODY + 1)}), 413)
            self.assertEqual(g({"X-Zenos-Machine": "pc-1", "Content-Length": "x"}), 400)
            self.assertEqual(g({"X-Zenos-Machine": "pc-1", "Content-Length": "100"}), 0)

    def test_over_http(self):
        import socket, threading, urllib.request, urllib.error
        with tempfile.TemporaryDirectory() as d:
            node = an.Node(os.path.join(d, "node"))
            k = Ed25519PrivateKey.generate()
            node.enroll("pc-1", base64.b64encode(k.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            import io, contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                threading.Thread(target=an.serve, args=(node, "127.0.0.1", port, None, None, 3600),
                                 daemon=True).start()
                time.sleep(0.5)

            def post(headers, body):
                req = urllib.request.Request("http://127.0.0.1:%d/v1/batch" % port, data=body, method="POST",
                                             headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        return r.status
                except urllib.error.HTTPError as e:
                    e.read(); e.close()
                    return e.code
            body = json.dumps({"machine": "pc-1", "chain": "guard", "from": 0, "records": []}).encode()
            self.assertEqual(post({}, body), 403)
            self.assertEqual(post({"X-Zenos-Machine": "pc-2"}, body), 403)
            other = json.dumps({"machine": "pc-9", "chain": "guard", "from": 0, "records": []}).encode()
            self.assertEqual(post({"X-Zenos-Machine": "pc-1"}, other), 403)     # named one machine, sent another's
            self.assertEqual(post({"X-Zenos-Machine": "pc-1"}, body), 403)      # its own, but unsigned


class OpenHolders(unittest.TestCase):
    """the network stays cut while the process that received L4+ plaintext, or anything it started, is alive; the
    user's own flag file cannot lift it"""
    def test_holders_and_their_children(self):
        import subprocess, importlib
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            os.environ["ZENOS_OPEN_KIDS"] = os.path.join(d, "kids.json")
            import zenos_netsentinel as ns
            importlib.reload(ns)
            path = os.path.join(d, "holders.json")
            parent = subprocess.Popen([sys.executable, "-c",
                                       "import subprocess,sys,time;subprocess.Popen(['sleep','30']);time.sleep(1.5)"])
            time.sleep(0.5)
            start = open("/proc/%d/stat" % parent.pid).read().rsplit(")", 1)[1].split()[19]
            with open(path, "w") as f:
                json.dump([{"pid": parent.pid, "start": start, "level": 4}], f)
            self.assertTrue(ns.holders_alive(path))                      # the holder and its child are recorded
            kids = [{"pid": p} for p in ns._KIDS]                     # followed in the sentinel's memory
            self.assertTrue(kids)
            self.assertEqual(len(json.load(open(path))), 1)              # the file is keyd's alone
            parent.wait()
            self.assertTrue(ns.holders_alive(path))                      # the holder exited, its child still holds
            importlib.reload(ns)                                         # the sentinel is restarted in between:
            self.assertTrue(ns.holders_alive(path))                      # the child it followed still holds
            for k in kids:
                os.kill(k["pid"], 9)
            time.sleep(0.3)
            self.assertFalse(ns.holders_alive(path))
            with open(path, "w") as f:
                json.dump([{"pid": os.getpid(), "start": "0", "level": 4}], f)   # a reused pid is not the holder
            self.assertFalse(ns.holders_alive(path))
            with open(path, "w") as f:
                json.dump([{"pid": os.getpid(), "start": open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19], "level": 3}], f)
            self.assertFalse(ns.holders_alive(path))                    # L3 does not cut the network


class HolderCgroups(unittest.TestCase):
    """keyd puts each L4+ holder in a cgroup of its own; whatever is born in it stays there, however the processes in
    between exit, so a child started and left between two looks still keeps the network cut"""
    def test_a_process_in_a_holder_cgroup_holds(self):
        import subprocess, importlib
        with tempfile.TemporaryDirectory() as d:
            cg = os.path.join(d, "cg")
            os.environ.update(ZENOS_HOLD_CGROUP=cg, ZENOS_OPEN_KIDS=os.path.join(d, "kids.json"),
                              ZENOS_OPEN_HOLDERS=os.path.join(d, "holders.json"))
            import zenos_keyd as kd, zenos_netsentinel as ns
            importlib.reload(kd); importlib.reload(ns)
            empty = os.path.join(d, "none.json")
            with open(empty, "w") as f:
                f.write("[]")
            p = subprocess.Popen(["sleep", "30"])
            try:
                start = open("/proc/%d/stat" % p.pid).read().rsplit(")", 1)[1].split()[19]
                kd.cgroup_hold([{"pid": p.pid, "start": start}], 4)
                g = os.path.join(cg, "L4-%d-%s" % (p.pid, start))
                self.assertEqual(open(os.path.join(g, "cgroup.procs")).read().split(), [str(p.pid)])
                self.assertTrue(ns.holders_alive(empty))           # not in keyd's list, not a known child: held anyway
                kd.cgroup_hold([{"pid": p.pid, "start": start}], 3)
                os.rename(g, os.path.join(cg, "moved"))            # only the L3 cgroup is left
                self.assertFalse(ns.holders_alive(empty))          # L3 does not cut the network
                os.rename(os.path.join(cg, "moved"), g)
            finally:
                p.kill(); p.wait()
            self.assertFalse(ns.holders_alive(empty))              # gone: nothing holds


class DropList(unittest.TestCase):
    """an anyone-can-receive service (webhook.site and the like) is cut at the first byte for every account, in
    monitor mode too; an address a listed destination shares is never cut"""
    def test_cut_for_a_person_too(self):
        import importlib
        import zenos_netsentinel as ns
        importlib.reload(ns)
        self.assertIn("webhook.site", ns.DROP_DEFAULT)
        ns.SYS["mode"] = "monitor"
        ns.drop_ips.clear(); ns.drop_ips.update({"203.0.113.9", "198.51.100.7"})
        ns.sys_ips.clear(); ns.sys_ips.add("198.51.100.7")       # also an update mirror's address
        ns.sys_seen.clear()
        ns.log = lambda rec: None
        ns.proc_info = lambda pid: {"pid": pid, "uid": 1000}       # a person's program
        self.assertTrue(ns.system_check(4242, "203.0.113.9", 443, "curl"))
        self.assertFalse(ns.system_check(4242, "198.51.100.7", 443, "apt"))
        self.assertFalse(ns.system_check(4242, "192.0.2.1", 443, "firefox"))   # anything else: not this rule


class RawSockets(unittest.TestCase):
    """a socket that writes below the packet filter (AF_PACKET, AF_XDP) is frozen unless a listed network program
    holds a packet socket; an XDP socket is never allowed"""
    def test_who_may_hold_one(self):
        import importlib
        import zenos_netsentinel as ns
        importlib.reload(ns)
        exe = {10: "/usr/sbin/NetworkManager", 11: "/usr/bin/python3.13", 12: "/usr/sbin/wpa_supplicant",
               13: "/usr/sbin/NetworkManager"}.get
        owners = {10: {1}, 11: {2}, 12: {3}, 13: {4}}
        bad = ns.raw_offenders({1, 2, 3}, {4}, owners, exe)
        self.assertEqual(sorted(bad), [(11, "packet"), (13, "xdp")])   # python's packet socket; any XDP socket
        self.assertEqual(ns.raw_offenders(set(), set(), {}, exe), [])
        self.assertEqual(ns.packet_inodes("sk RefCnt Type Proto Iface R Rmem User Inode\n"
                                          "ffff 3 3 88cc 2 1 0 0 41234\n"), {41234})

    def test_a_packet_socket_opened_here_is_found(self):
        import importlib, socket
        import zenos_netsentinel as ns
        importlib.reload(ns)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except (PermissionError, OSError, AttributeError):
            self.skipTest("no CAP_NET_RAW here")
        try:
            with open("/proc/net/packet") as f:
                pk = ns.packet_inodes(f.read())
            ino = os.fstat(s.fileno()).st_ino
            self.assertIn(ino, pk)
            owners = ns.socket_owners({ino})
            self.assertIn(os.getpid(), owners)
            bad = ns.raw_offenders(pk, set(), {os.getpid(): owners[os.getpid()]}, lambda p: sys.executable)
            self.assertEqual(bad, [(os.getpid(), "packet")])
        finally:
            s.close()

if __name__ == "__main__":
    unittest.main()
