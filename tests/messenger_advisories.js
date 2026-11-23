// Fixes for reports made through private security advisories (November 2026):
//  - GHSA-q7qh-2x6r-5pjx: the messenger refuses to start when the list of distrusted CA keys is missing
//  - GHSA-g59c-684x-c9gw: an external call server carries at most L2 calls unless the host's root trusts it
//   node tests/messenger_advisories.js
"use strict";
const fs = require("fs"), os = require("os"), path = require("path"), assert = require("assert"), { spawnSync } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
let fail = 0; const check = (n, c) => { console.log((c ? "ok   " : "FAIL ") + n); if (!c) fail++; };

// 1. distrust.js on its own, with no zdistrust.js next to it nor installed
const d = fs.mkdtempSync(path.join(os.tmpdir(), "zdist-"));
fs.mkdirSync(path.join(d, "messenger")); fs.copyFileSync(path.join(MSG, "distrust.js"), path.join(d, "messenger", "distrust.js"));
const installed = fs.existsSync("/usr/lib/zenos/zdistrust.js");
const r = spawnSync(process.execPath, ["-e", "require('./messenger/distrust.js'); console.log('started')"], { cwd: d, encoding: "utf8" });
if (installed) console.log("skip  distrust missing (installed here at /usr/lib/zenos)");
else check("without the distrust list the program does not start", r.status !== 0 && /zdistrust\.js is missing/.test(r.stderr) && !/started/.test(r.stdout));
const r2 = spawnSync(process.execPath, ["-e", "const d=require('./messenger/distrust.js'); console.log(typeof d.blocked)"], { cwd: path.join(__dirname, ".."), encoding: "utf8" });
check("with the list it loads", r2.status === 0 && /function/.test(r2.stdout));
fs.rmSync(d, { recursive: true, force: true });

// 2. the call-server cap, on a running relay
const crypto = require("crypto"), { spawn } = require("child_process");
const wait = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await f(); if (v) return v; } catch {} await new Promise((z) => setTimeout(z, 250)); } return null; };
(async () => {
  const H = fs.mkdtempSync(path.join(os.tmpdir(), "zcall-")), port = 19500 + Math.floor(Math.random() * 300), R = `http://127.0.0.1:${port}`;
  const ADMIN = crypto.randomBytes(12).toString("hex"), TRUST = path.join(H, "call-servers.json");
  const p = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME: H, ZENOS_RELAY_PORT: String(port), ZENOS_RELAY_ADMIN: ADMIN,
    ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_CALL_TRUST: TRUST }, stdio: "ignore" });
  try {
    await wait(() => fetch(R + "/trust").then((r) => r.ok));
    const add = (name, url) => fetch(R + "/call/servers", { method: "POST", headers: { "Content-Type": "application/json", "X-Zenos-Admin": ADMIN },
      body: JSON.stringify({ add: { name, url, key: "k", secret: "s", maxLevel: 5 } }) }).then((r) => r.json());
    const lvl = (x, id) => (x.servers.find((s) => s.id === id) || {}).maxLevel;
    check("an external call server asking for L5 gets L2", lvl(await add("evil", "wss://attacker.example/"), "evil") === 2);
    fs.writeFileSync(TRUST, JSON.stringify({ trusted: ["calls.ministry.example"] }));
    check("a server the host's root lists keeps the level asked for", lvl(await add("ours", "wss://calls.ministry.example"), "ours") === 5);
  } finally { p.kill(); fs.rmSync(H, { recursive: true, force: true }); }
  console.log(fail ? `${fail} FAILED` : "ALL OK"); process.exit(fail ? 1 : 0);
  })().catch((e) => { console.error(e); process.exit(1); });
