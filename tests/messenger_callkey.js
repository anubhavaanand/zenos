// Call keys in messages: used only from someone in the call who belongs to its conversation, for this call, and shaped
// like a key. Anyone else who can message you cannot switch (and so cut off) your call.   node tests/messenger_callkey.js
const fs = require("fs"), path = require("path");
global.window = { LivekitClient: { ExternalE2EEKeyProvider: class {} } };
eval(fs.readFileSync(path.join(__dirname, "..", "messenger", "zcall.js"), "utf8"));
const ok = window.ZCall.keyMessageOk;
let fail = 0; const check = (n, c) => { console.log((c ? "ok   " : "FAIL ") + n); if (!c) fail++; };
const key = Buffer.alloc(32, 9).toString("base64");
const dm = { room: "r1", me: "tk", target: { to: "sato" }, members: ["tk", "sato"] };
const ch = { room: "r2", me: "tk", target: { ch: "ops" }, members: ["tk", "sato", "ito"] };
const msg = (o) => ({ kind: "callkey", dir: "in", from: "sato", ch: null, ev: { room: "r1", key, idx: 1 }, ...o });
check("the DM's other person, in the call: used", ok(msg({}), dm));
check("a channel member in the call, writing in the call's channel: used", ok(msg({ from: "ito", ch: "ops", ev: { room: "r2", key, idx: 3 } }), ch));
check("someone not in the call: refused", !ok(msg({ from: "mallory" }), { ...dm, members: ["tk", "sato", "mallory"].slice(0, 2) }));
check("in the call but not the DM's other person: refused", !ok(msg({ from: "ito" }), { ...dm, members: ["tk", "sato", "ito"] }));
check("a DM key claiming a channel: refused", !ok(msg({ ch: "ops" }), dm));
check("a channel call, key sent outside the channel: refused", !ok(msg({ from: "ito", ev: { room: "r2", key, idx: 3 } }), ch));
check("another call's room: refused", !ok(msg({ ev: { room: "r9", key, idx: 1 } }), dm));
check("my own message: refused", !ok(msg({ from: "tk" }), dm) && !ok(msg({ dir: "out" }), dm));
check("a short key: refused", !ok(msg({ ev: { room: "r1", key: Buffer.alloc(16).toString("base64"), idx: 1 } }), dm));
check("not base64: refused", !ok(msg({ ev: { room: "r1", key: "!".repeat(43) + "=", idx: 1 } }), dm));
check("index out of range: refused", !ok(msg({ ev: { room: "r1", key, idx: 16 } }), dm) && !ok(msg({ ev: { room: "r1", key, idx: "1" } }), dm));
check("not in a call: refused", !ok(msg({}), { ...dm, room: null }));
// ui.html takes keys only through this rule
const ui = fs.readFileSync(path.join(__dirname, "..", "messenger", "ui.html"), "utf8");
check("the page applies keys from messages only through the rule", (ui.match(/ZCall\.applyKey\(m\./g) || []).length === 1 && ui.includes("ZCall.keyMessageOk(m,kctx)"));
// times and relay-supplied membership details reach the page as text only
const hmF = new Function("esc", ui.match(/const hm=t=>[^;]+;/)[0] + ui.match(/const dayt=t=>[^;]+;/)[0] + "return dayt;");
const escF = new Function(ui.match(/const esc=s=>[^\n]+;/)[0] + "return esc;")();
check("a time from a sender is shown as text", !/[<>]/.test(hmF(escF)("0000x-<!-- 00:00")) && !/[<>]/.test(hmF(escF)("9999x--->x 00:00")));
check("the relay's approval level and membership history are escaped", ui.includes("(L${esc(String(a.level))})") && ui.includes("${esc(l.act)}"));
console.log(fail ? `${fail} FAILED` : "ALL OK"); process.exit(fail ? 1 : 0);
