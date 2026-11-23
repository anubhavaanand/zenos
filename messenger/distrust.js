// Refuse compromised / distrusted CA certificates on every TLS connection (system/lib/zdistrust.js).
// Installed ZENOS also loads it into every Node program through NODE_OPTIONS; requiring it twice is harmless.
"use strict";
const fs = require("fs");
const path = require("path");
const lib = [path.join(__dirname, "../system/lib/zdistrust.js"), "/usr/lib/zenos/zdistrust.js"].find((p) => fs.existsSync(p));
// Without the list the program must not run trusting every CA: refuse to start instead (GHSA-q7qh-2x6r-5pjx).
if (!lib) throw new Error("zdistrust.js is missing: refusing to start without the list of distrusted CA keys");
module.exports = require(lib);
