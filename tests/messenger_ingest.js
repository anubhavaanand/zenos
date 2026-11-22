// What a ZENOS Messages client takes in from another account of its own organization (client.js receive/ingest):
// a message that names a channel counts there only when its sender is a member of that channel (so a non-member
// cannot plant a call, its key or its level in a channel call); event details must have the shape the page draws
// (a malformed one is dropped instead of breaking the page); and a time that is not a time is replaced.
//   node tests/messenger_ingest.js   (needs messenger/node_modules)
const path = require("path"), os = require("os"), fs = require("fs"), crypto = require("crypto"), { spawn } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
const S = require(require.resolve("@signalapp/libsignal-client", { paths: [MSG] }));
const b64 = (u) => Buffer.from(u).toString("base64"), ub = (s) => Buffer.from(s, "base64");
const sha = (x) => crypto.createHash("sha256").update(String(x)).digest("hex");
const base = 19100 + Math.floor(Math.random() * 300), R = `http://127.0.0.1:${base}`, Z = `http://127.0.0.1:${base + 10}`;
const ADMIN = crypto.randomBytes(12).toString("hex");
const procs = [], homes = [];
const home = () => { const h = fs.mkdtempSync(path.join(os.tmpdir(), "zing-")); homes.push(h); return h; };
const run = (args, env) => { const p = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: "ignore" }); procs.push(p); return p; };
const finish = (c) => { for (const p of procs) p.kill(); for (const h of homes) fs.rmSync(h, { recursive: true, force: true }); process.exit(c); };
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const wait = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await f(); if (v) return v; } catch {} await new Promise((z) => setTimeout(z, 250)); } return null; };
(async () => {
  const RH = home(), ZH = home();
  run([path.join(MSG, "relay.js")], { HOME: RH, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(base), ZENOS_RELAY_ADMIN: ADMIN });
  await wait(() => fetch(R + "/trust").then((r) => r.ok));
  run([path.join(MSG, "client.js"), "zenos", String(base + 10)], { HOME: ZH, ZENOS_RELAY: R });
  const lk = () => { try { return fs.readFileSync(path.join(ZH, ".local/share/zenos/msg/store/zenos/local.key"), "utf8"); } catch { return ""; } };
  const api = async (p) => (await fetch(Z + p, { headers: { "X-Zenos-Local": lk() } })).json();
  await wait(async () => lk() && (await fetch(Z + "/api/me", { headers: { "X-Zenos-Local": lk() } })).ok, 30000);

  // the test speaks for sato, a colleague in zenos's organization, with the same libsignal the client uses
  const st = { idkp: S.IdentityKeyPair.generate(), sessions: {}, ids: {} };
  const sess = new (class extends S.SessionStore { async saveSession(a, r) { st.sessions[a.toString()] = r.serialize(); }
    async getSession(a) { const x = st.sessions[a.toString()]; return x ? S.SessionRecord.deserialize(x) : null; }
    async getExistingSessions(as) { return (await Promise.all(as.map((a) => this.getSession(a)))).filter(Boolean); } })();
  const ident = new (class extends S.IdentityKeyStore { async getIdentityKey() { return st.idkp.privateKey; } async getLocalRegistrationId() { return 77; }
    async saveIdentity(a, k) { st.ids[a.name()] = k; return S.IdentityChange.NewOrUnchanged; } async isTrustedIdentity() { return true; } async getIdentity(a) { return st.ids[a.name()] || null; } })();
  const signed = (method, p, obj) => { const raw = obj ? JSON.stringify(obj) : "", ts = String(Date.now());
    const sig = b64(st.idkp.privateKey.sign(Buffer.from(`${method} ${p} ${ts} ${sha(raw)}`)));
    return fetch(R + p, { method, headers: { "Content-Type": "application/json", "X-Zenos-Auth": `sato ${ts} ${sig}` }, body: raw || undefined }).then((r) => r.json()); };
  await fetch(R + "/keys/sato", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: "sato", identity: b64(st.idkp.publicKey.serialize()) }) });
  const admin = (obj) => fetch(R + "/channels", { method: "POST", headers: { "Content-Type": "application/json", "X-Zenos-Admin": ADMIN }, body: JSON.stringify(obj) }).then((r) => r.json());
  await admin({ id: "board", name: "board", level: 3, members: ["zenos", "tanaka"] });       // sato is not a member
  await admin({ id: "team", name: "team", level: 1, members: ["zenos", "sato"] });          // sato is a member
  const b = await wait(async () => { const x = await signed("GET", "/keys/zenos"); return x && x.intro ? x : null; });
  await S.processPreKeyBundle(S.PreKeyBundle.new(b.regId, 1, b.preKey ? b.preKey.id : null, b.preKey ? S.PublicKey.deserialize(ub(b.preKey.pub)) : null,
    b.signed.id, S.PublicKey.deserialize(ub(b.signed.pub)), ub(b.signed.sig), S.PublicKey.deserialize(ub(b.identity)),
    b.kyber.id, S.KEMPublicKey.deserialize(ub(b.kyber.pub)), ub(b.kyber.sig)), S.ProtocolAddress.new("zenos", 1), S.ProtocolAddress.new("sato", 1), sess, ident);
  const cert = S.SenderCertificate.deserialize(ub((await fetch(R + "/cert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ acc: "sato", identity: b64(st.idkp.publicKey.serialize()) }) }).then((r) => r.json())).cert));
  const put = async (m) => { const env = await S.sealedSenderEncryptMessage(Buffer.from(JSON.stringify(m)), S.ProtocolAddress.new("zenos", 1), cert, sess, ident);
    await fetch(R + "/deliver", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mbx: b.intro, uak: null, body: b64(env) }) }); };
  const now = new Date().toISOString().slice(0, 19) + "+0000";

  await put({ kind: "call", ch: "board", level: 1, t: now, id: "c1", ev: { status: "start", room: "r", key: b64(crypto.randomBytes(32)) } });
  await put({ kind: "msg", ch: "board", level: 1, t: now, id: "m1", text: "planted in a channel I am not in" });
  await put({ kind: "msg", ch: "team", level: 1, t: now, id: "m2", text: "in my own channel" });
  await put({ kind: "event", level: 1, t: now, id: "e1", ev: { title: "x", date: "2026-12-01", attendees: 5 } });
  await put({ kind: "msg", level: 1, t: "0000x-<!-- 00:00", id: "m3", text: "odd time" });
  const team = await wait(async () => { const x = await api("/api/channel-messages?ch=team"); return x.length ? x : null; }, 20000);
  check("a member's message in their channel arrives", team && team.some((m) => m.id === "m2"), team);
  const all = await wait(async () => { const x = await api("/api/all"); return x.some((m) => m.id === "m3") ? x : null; }, 20000) || [];
  check("a non-member's message naming the channel is dropped", !all.some((m) => m.id === "m1"), all.map((m) => m.id));
  check("a non-member cannot start a call (or set its key) in the channel", !all.some((m) => m.id === "c1"), all.map((m) => m.id));
  check("an event whose attendees are not a list of names is dropped", !all.some((m) => m.id === "e1"), all.map((m) => m.id));
  const m3 = all.find((m) => m.id === "m3");
  check("a time that is not a time is replaced by the time it arrived", m3 && /^\d{4}-\d{2}-\d{2}T/.test(m3.t) && !/</.test(m3.t), m3);
  const audit = fs.readFileSync(path.join(ZH, ".local/share/zenos/audit.log"), "utf8");
  check("the drops are written to the audit log", /not a member of the channel/.test(audit) && /malformed/.test(audit));
  console.log(fail ? `${fail} FAILED` : "ALL OK"); finish(fail ? 1 : 0);
})().catch((e) => { console.error(e); finish(1); });
