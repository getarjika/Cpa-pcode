require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
const db = new Database(process.env.DB_PATH || "database.db");
const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_SECONDS = 60 * 60;
const CODE_TTL_SECONDS = 30 * 60;

if (!process.env.POSTBACK_SECRET || !process.env.REDEEM_API_KEY) {
  throw new Error("POSTBACK_SECRET and REDEEM_API_KEY must be set in .env");
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.static("public"));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});
app.use("/api/", apiLimiter);

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  verified_at INTEGER
);

CREATE TABLE IF NOT EXISTS pcodes (
  code TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);

CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`);

const now = () => Math.floor(Date.now() / 1000);
const randomHex = (bytes = 24) => crypto.randomBytes(bytes).toString("hex");

function makePCode() {
  // 50 bits of randomness, with a human-readable prefix.
  return "CPA-" + crypto.randomBytes(7).toString("hex").slice(0, 10).toUpperCase();
}

function safeEqualString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function issueCodeForSession(sessionId) {
  const existing = db.prepare(
    "SELECT code FROM pcodes WHERE session_id = ?"
  ).get(sessionId);
  if (existing) return existing.code;

  // Retry in the extremely unlikely event of a code collision.
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = makePCode();
    try {
      db.prepare(`
        INSERT INTO pcodes (code, session_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(code, sessionId, now(), now() + CODE_TTL_SECONDS);
      return code;
    } catch (err) {
      if (!String(err.code || "").startsWith("SQLITE_CONSTRAINT")) throw err;
    }
  }
  throw new Error("Could not allocate unique P-Code");
}

// Create a task session. The ID is a bearer token: do not expose it in logs.
app.post("/api/start", express.json({ limit: "4kb" }), (req, res) => {
  const sessionId = randomHex(24);
  const created = now();

  db.prepare(`
    INSERT INTO sessions (id, created_at, expires_at)
    VALUES (?, ?, ?)
  `).run(sessionId, created, created + SESSION_TTL_SECONDS);

  res.status(201).json({
    success: true,
    session_id: sessionId,
    expires_in_seconds: SESSION_TTL_SECONDS,
    instructions: "Complete the advertiser's app-install task. The trusted tracking provider must confirm installation before a P-Code can be issued."
  });
});

// Provider webhook. Signature is HMAC-SHA256 of the exact raw request body.
// Configure the provider to send x-cpa-signature: <hex digest>.
app.post(
  "/api/provider/install-callback",
  express.raw({ type: "application/json", limit: "16kb" }),
  (req, res) => {
    const signature = req.get("x-cpa-signature") || "";
    const expected = crypto
      .createHmac("sha256", process.env.POSTBACK_SECRET)
      .update(req.body)
      .digest("hex");

    if (!/^[a-f0-9]{64}$/i.test(signature) ||
        !safeEqualString(signature.toLowerCase(), expected)) {
      return res.status(401).json({ success: false, error: "Invalid signature" });
    }

    let payload;
    try {
      payload = JSON.parse(req.body.toString("utf8"));
    } catch {
      return res.status(400).json({ success: false, error: "Invalid JSON" });
    }

    const { event_id, session_id, event_type } = payload;
    if (
      typeof event_id !== "string" || event_id.length < 8 || event_id.length > 128 ||
      typeof session_id !== "string" || !/^[a-f0-9]{48}$/.test(session_id) ||
      event_type !== "install_verified"
    ) {
      return res.status(400).json({ success: false, error: "Invalid event payload" });
    }

    const session = db.prepare(
      "SELECT id, expires_at, verified_at FROM sessions WHERE id = ?"
    ).get(session_id);

    if (!session || session.expires_at < now()) {
      return res.status(404).json({ success: false, error: "Session not found or expired" });
    }

    try {
      const tx = db.transaction(() => {
        db.prepare(`
          INSERT INTO events (event_id, session_id, event_type, created_at)
          VALUES (?, ?, ?, ?)
        `).run(event_id, session_id, event_type, now());

        db.prepare(`
          UPDATE sessions SET verified_at = COALESCE(verified_at, ?)
          WHERE id = ?
        `).run(now(), session_id);

        return issueCodeForSession(session_id);
      });

      tx();
      return res.json({ success: true, received: true });
    } catch (err) {
      if (String(err.code || "").startsWith("SQLITE_CONSTRAINT")) {
        return res.status(409).json({ success: false, error: "Duplicate event" });
      }
      console.error("Callback processing error:", err.message);
      return res.status(500).json({ success: false, error: "Internal error" });
    }
  }
);

// Local-only simulation endpoint. Never enable this on a public production site.
if (process.env.ENABLE_DEMO_ENDPOINT === "true") {
  app.post("/api/demo/simulate-install", express.json({ limit: "4kb" }), (req, res) => {
    const { session_id, demo_key } = req.body || {};
    if (!safeEqualString(demo_key, process.env.POSTBACK_SECRET)) {
      return res.status(401).json({ success: false, error: "Invalid demo key" });
    }
    if (typeof session_id !== "string" || !/^[a-f0-9]{48}$/.test(session_id)) {
      return res.status(400).json({ success: false, error: "Invalid session_id" });
    }

    const session = db.prepare(
      "SELECT id, expires_at FROM sessions WHERE id = ?"
    ).get(session_id);
    if (!session || session.expires_at < now()) {
      return res.status(404).json({ success: false, error: "Session not found or expired" });
    }

    const eventId = "demo_" + randomHex(16);
    try {
      const tx = db.transaction(() => {
        db.prepare(`
          INSERT INTO events (event_id, session_id, event_type, created_at)
          VALUES (?, ?, 'install_verified', ?)
        `).run(eventId, session_id, now());
        db.prepare(`
          UPDATE sessions SET verified_at = COALESCE(verified_at, ?)
          WHERE id = ?
        `).run(now(), session_id);
        return issueCodeForSession(session_id);
      });
      tx();
      res.json({ success: true, simulated: true, message: "Demo event recorded. This does NOT prove a real app install." });
    } catch (err) {
      console.error("Demo error:", err.message);
      res.status(500).json({ success: false, error: "Could not simulate event" });
    }
  });
}

// Get P-Code only after a trusted provider callback has verified the install.
app.get("/api/code/:sessionId", (req, res) => {
  const sessionId = req.params.sessionId;
  if (!/^[a-f0-9]{48}$/.test(sessionId)) {
    return res.status(400).json({ success: false, error: "Invalid session" });
  }

  const session = db.prepare(
    "SELECT id, expires_at, verified_at FROM sessions WHERE id = ?"
  ).get(sessionId);

  if (!session || session.expires_at < now()) {
    return res.status(404).json({ success: false, error: "Session not found or expired" });
  }
  if (!session.verified_at) {
    return res.status(403).json({ success: false, error: "Install has not been verified" });
  }

  const code = db.prepare(`
    SELECT code, expires_at, used_at
    FROM pcodes WHERE session_id = ?
  `).get(sessionId);

  if (!code || code.expires_at < now() || code.used_at) {
    return res.status(404).json({ success: false, error: "P-Code unavailable, expired, or already used" });
  }

  res.json({ success: true, p_code: code.code, expires_at: code.expires_at });
});

// Redeem endpoint for your CPA platform/server only.
// Send x-api-key from your trusted server; do not put this key in frontend JS.
app.post("/api/redeem", express.json({ limit: "4kb" }), (req, res) => {
  const apiKey = req.get("x-api-key") || "";
  if (!safeEqualString(apiKey, process.env.REDEEM_API_KEY)) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  const { code } = req.body || {};
  if (typeof code !== "string" || !/^CPA-[A-F0-9]{10}$/.test(code)) {
    return res.status(400).json({ success: false, error: "Invalid code format" });
  }

  const result = db.prepare(`
    UPDATE pcodes
    SET used_at = ?
    WHERE code = ?
      AND used_at IS NULL
      AND expires_at > ?
  `).run(now(), code, now());

  if (result.changes !== 1) {
    return res.status(404).json({
      success: false,
      valid: false,
      error: "Invalid, expired, or already redeemed"
    });
  }

  res.json({ success: true, valid: true, message: "Task verified and code redeemed" });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`CPA P-Code server running at http://localhost:${PORT}`);
});
