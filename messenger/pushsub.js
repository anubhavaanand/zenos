// ZENOS Messages: what a phone may hand in as its Web Push subscription.
// The PC later sends to the subscription's endpoint, so only an HTTPS address at a browser maker's push service is
// taken, with the two keys of the sizes the Web Push standard gives (RFC 8291: a P-256 point and a 16-byte secret).
// Anything else (an address on the local network, another port, a name with a password in it) is refused.
"use strict";
const HOSTS = [/^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/,
  /^push\.services\.mozilla\.com$/, /^(?:[a-z0-9-]+\.)*push\.apple\.com$/, /^(?:[a-z0-9-]+\.)*notify\.windows\.com$/];
const B64U = /^[A-Za-z0-9_-]+={0,2}$/;
const bytes = (s) => (typeof s === "string" && s.length <= 200 && B64U.test(s) ? Buffer.from(s, "base64url").length : -1);

function pushSub(sub) {
  if (!sub || typeof sub !== "object" || typeof sub.endpoint !== "string" || sub.endpoint.length > 1024) return null;
  let u;
  try { u = new URL(sub.endpoint); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password || u.port || !HOSTS.some((h) => h.test(u.hostname))) return null;
  const k = sub.keys || {};
  if (bytes(k.p256dh) !== 65 || bytes(k.auth) !== 16) return null;
  const exp = sub.expirationTime;
  if (exp !== null && exp !== undefined && !Number.isFinite(exp)) return null;
  return { endpoint: u.href, expirationTime: exp ?? null, keys: { p256dh: k.p256dh, auth: k.auth } };
}

// where a notification may take the person: a page of this app only
function sameOriginPath(url) {
  const s = String(url || "/");
  return /^\/(?![/\\])[^\s]*$/.test(s) ? s : "/";
}

module.exports = { pushSub, sameOriginPath, HOSTS };
