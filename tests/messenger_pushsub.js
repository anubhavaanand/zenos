// Messenger push subscriptions: only a browser maker's HTTPS push address with keys of the right sizes is kept, and a
// notification opens only a page of the app.   node tests/messenger_pushsub.js
const { pushSub, sameOriginPath } = require("../messenger/pushsub");
const fs = require("fs"), path = require("path");
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const keys = { p256dh: Buffer.alloc(65, 4).toString("base64url"), auth: Buffer.alloc(16, 7).toString("base64url") };
const ok = (endpoint, k = keys) => pushSub({ endpoint, expirationTime: null, keys: k });
for (const e of ["https://fcm.googleapis.com/fcm/send/abc", "https://web.push.apple.com/QGx", "https://updates.push.services.mozilla.com/wpush/v2/x",
                 "https://wns2-par02p.notify.windows.com/w/?token=x"])
  check("a push service address is kept: " + new URL(e).host, ok(e) && ok(e).endpoint === e, ok(e));
for (const e of ["http://fcm.googleapis.com/fcm/send/abc", "https://192.168.1.10/admin", "https://localhost/x", "https://fcm.googleapis.com:8443/x",
                 "https://u:p@fcm.googleapis.com/x", "https://fcm.googleapis.com.evil.example/x", "https://evilpush.apple.com.example/x",
                 "https://notpush.apple.com/x", "file:///etc/passwd", "javascript:alert(1)", "not a url"])
  check("refused: " + e, ok(e) === null, ok(e));
check("refused: no keys", pushSub({ endpoint: "https://fcm.googleapis.com/x" }) === null);
check("refused: a short key", ok("https://fcm.googleapis.com/x", { ...keys, p256dh: Buffer.alloc(32).toString("base64url") }) === null);
check("refused: a key that is not base64url", ok("https://fcm.googleapis.com/x", { ...keys, auth: "!!!!" }) === null);
check("refused: not an object", pushSub("https://fcm.googleapis.com/x") === null && pushSub(null) === null);
check("only the known fields are kept", JSON.stringify(Object.keys(pushSub({ endpoint: "https://fcm.googleapis.com/x", keys, extra: 1 }))) === '["endpoint","expirationTime","keys"]');
for (const [u, want] of [["/", "/"], ["/#c:general", "/#c:general"], ["//evil.example/", "/"], ["/\\evil.example", "/"],
                         ["https://evil.example/", "/"], ["javascript:alert(1)", "/"], [undefined, "/"]])
  check(`notification link ${u} -> ${want}`, sameOriginPath(u) === want, sameOriginPath(u));
// the service worker carries the same rule (it cannot load the module)
const sw = fs.readFileSync(path.join(__dirname, "..", "messenger", "sw.js"), "utf8");
check("the service worker opens only pages of the app", sw.includes(String(/^\/(?![/\\])[^\s]*$/)));
console.log(fail ? `${fail} FAILED` : "ALL OK"); process.exit(fail ? 1 : 0);
