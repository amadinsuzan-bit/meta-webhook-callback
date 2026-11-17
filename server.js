const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN || "";
const APP_SECRET = process.env.META_APP_SECRET || "";
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "events.sqlite");
const META_APP_ID = process.env.META_APP_ID || "";
const GRAPH_VERSION = (process.env.META_GRAPH_VERSION || "v24.0").replace(/^v?/, "v");
const LOGIN_SCOPES = process.env.META_LOGIN_SCOPES || "public_profile,pages_show_list,pages_read_engagement,instagram_basic";
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || "";

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_type TEXT,
    received_at TEXT NOT NULL,
    headers TEXT,
    payload TEXT NOT NULL,
    signature_valid INTEGER,
    status TEXT NOT NULL DEFAULT 'received',
    note TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at DESC);
  CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS meta_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_token TEXT NOT NULL,
    iv TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    token_type TEXT,
    expires_at TEXT,
    scopes TEXT,
    created_at TEXT NOT NULL
  );
`);

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, "public")));

// Keep the exact raw bytes for Meta's X-Hub-Signature-256 verification.
app.use("/webhook", express.raw({ type: "*/*", limit: "2mb" }));
app.use("/callback", express.raw({ type: "*/*", limit: "2mb" }));
app.use(express.json({ limit: "1mb" }));


function getEncryptionKey() {
  if (!/^[a-fA-F0-9]{64}$/.test(TOKEN_ENCRYPTION_KEY)) throw new Error("TOKEN_ENCRYPTION_KEY must be a 64-character (32-byte) hex string.");
  return Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
}
function encryptToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return { encrypted: encrypted.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}
function decryptToken(row) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", getEncryptionKey(), Buffer.from(row.iv, "base64"));
  decipher.setAuthTag(Buffer.from(row.auth_tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(row.encrypted_token, "base64")), decipher.final()]).toString("utf8");
}
function oauthRedirectUri(req) {
  const proto = req.get("x-forwarded-proto")?.split(",")[0] || req.protocol;
  return `${proto}://${req.get("host")}/auth/facebook/callback`;
}
async function graphTokenRequest(params) {
  const url = `https://graph.facebook.com/${GRAPH_VERSION}/oauth/access_token?${new URLSearchParams(params)}`;
  const response = await fetch(url, { method: "GET", headers: { accept: "application/json" } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.error || !data.access_token) {
    const message = data.error?.message || `Meta token request failed (${response.status}).`;
    throw new Error(message);
  }
  return data;
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function verifyMetaSignature(rawBody, signatureHeader) {
  if (!APP_SECRET) return null; // Not configured: accept but mark unverified.
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(rawBody).digest("hex");
  return safeEqual(expected, signatureHeader);
}
function insertEvent({ source, eventType, req, payload, signatureValid = null, status = "received", note = null }) {
  const result = db.prepare(`
    INSERT INTO events (source,event_type,received_at,headers,payload,signature_valid,status,note)
    VALUES (@source,@eventType,@receivedAt,@headers,@payload,@signatureValid,@status,@note)
  `).run({
    source, eventType: eventType || "unknown", receivedAt: new Date().toISOString(),
    headers: JSON.stringify({
      "user-agent": req.get("user-agent") || "",
      "content-type": req.get("content-type") || "",
      "x-hub-signature-256": req.get("x-hub-signature-256") || ""
    }),
    payload: typeof payload === "string" ? payload : JSON.stringify(payload),
    signatureValid: signatureValid === null ? null : (signatureValid ? 1 : 0),
    status, note
  });
  return Number(result.lastInsertRowid);
}
function parseRaw(req) {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");
  const text = raw.toString("utf8");
  try { return { raw, text, json: JSON.parse(text) }; }
  catch { return { raw, text, json: { raw_text: text } }; }
}
function dashboardAuth(req, res, next) {
  if (!DASHBOARD_PASSWORD) return res.status(503).json({ error: "DASHBOARD_PASSWORD is not configured." });
  const supplied = req.get("x-dashboard-password") || req.query.password || "";
  if (!safeEqual(supplied, DASHBOARD_PASSWORD)) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Meta webhook subscription verification (GET).
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && VERIFY_TOKEN && safeEqual(token, VERIFY_TOKEN)) {
    return res.status(200).type("text/plain").send(String(challenge || ""));
  }
  return res.sendStatus(403);
});

// Meta sends webhook notifications (POST).
app.post("/webhook", (req, res) => {
  const { raw, json } = parseRaw(req);
  const valid = verifyMetaSignature(raw, req.get("x-hub-signature-256"));
  if (valid === false) {
    insertEvent({ source: "meta", eventType: "signature_rejected", req, payload: json, signatureValid: false, status: "rejected", note: "Invalid X-Hub-Signature-256" });
    return res.sendStatus(401);
  }
  const objectType = json.object || "meta";
  const entryTypes = Array.isArray(json.entry) ? json.entry.map(e => e.changes?.map(c => c.field).filter(Boolean) || []).flat() : [];
  const eventType = [...new Set(entryTypes)].join(",") || objectType;
  insertEvent({ source: "meta", eventType, req, payload: json, signatureValid: valid, status: "received", note: valid === null ? "APP_SECRET not configured; signature not verified" : "Meta event accepted" });
  // Acknowledge quickly. Do lengthy processing asynchronously in a worker/queue if needed.
  return res.sendStatus(200);
});

// Facebook Login deauthorization callback. Meta sends a signed_request form field.
app.post("/facebook/deauthorize", express.urlencoded({ extended: false, limit: "256kb" }), (req, res) => {
  const signedRequest = req.body?.signed_request || "";
  let decoded = { signed_request_present: Boolean(signedRequest) };
  let signatureValid = null;
  if (signedRequest && APP_SECRET) {
    const parts = signedRequest.split(".");
    if (parts.length === 2) {
      try {
        const signature = Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64");
        const expected = crypto.createHmac("sha256", APP_SECRET).update(parts[1]).digest();
        signatureValid = signature.length === expected.length && crypto.timingSafeEqual(signature, expected);
        const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
        decoded = { ...payload, signed_request_present: true };
      } catch { signatureValid = false; }
    } else signatureValid = false;
  }
  const id = insertEvent({ source: "facebook_login", eventType: "deauthorization", req, payload: decoded, signatureValid, status: signatureValid === false ? "rejected" : "received", note: "Deauthorization callback captured. Implement account unlinking for your own user database." });
  // Meta expects a JSON response with a confirmation code.
  return res.status(signatureValid === false ? 401 : 200).json({ url: process.env.FACEBOOK_DEAUTH_STATUS_URL || "", confirmation_code: `deauth-${id}` });
});

// Facebook Login data deletion callback. Meta posts a signed_request.
app.post("/facebook/data-deletion", express.urlencoded({ extended: false, limit: "256kb" }), (req, res) => {
  const signedRequest = req.body?.signed_request || "";
  let decoded = { signed_request_present: Boolean(signedRequest) };
  let signatureValid = null;
  if (signedRequest && APP_SECRET) {
    const parts = signedRequest.split(".");
    if (parts.length === 2) {
      try {
        const signature = Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64");
        const expected = crypto.createHmac("sha256", APP_SECRET).update(parts[1]).digest();
        signatureValid = signature.length === expected.length && crypto.timingSafeEqual(signature, expected);
        decoded = { ...JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")), signed_request_present: true };
      } catch { signatureValid = false; }
    } else signatureValid = false;
  }
  const id = insertEvent({ source: "facebook_login", eventType: "data_deletion", req, payload: decoded, signatureValid, status: signatureValid === false ? "rejected" : "received", note: "Deletion request captured. Configure a deletion workflow and return a user-facing status URL." });
  return res.status(signatureValid === false ? 401 : 200).json({
    url: process.env.DATA_DELETION_STATUS_URL || "",
    confirmation_code: `delete-${id}`
  });
});

// Facebook Login OAuth: exchange authorization code -> short-lived token -> long-lived token.
app.get("/auth/facebook", (req, res) => {
  if (!META_APP_ID || !APP_SECRET) return res.status(503).send("Set META_APP_ID and META_APP_SECRET in Railway Variables first.");
  const state = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO oauth_states (state_hash, created_at) VALUES (?, ?)").run(crypto.createHash("sha256").update(state).digest("hex"), Date.now());
  db.prepare("DELETE FROM oauth_states WHERE created_at < ?").run(Date.now() - 10 * 60 * 1000);
  const params = new URLSearchParams({ client_id: META_APP_ID, redirect_uri: oauthRedirectUri(req), state, response_type: "code", scope: LOGIN_SCOPES });
  return res.redirect(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth?${params}`);
});

app.get("/auth/facebook/callback", async (req, res) => {
  try {
    if (req.query.error) return res.status(400).send(`Facebook Login was not completed: ${String(req.query.error_description || req.query.error).replace(/[<>]/g, "")}`);
    const state = String(req.query.state || "");
    const stateHash = crypto.createHash("sha256").update(state).digest("hex");
    const stateRow = db.prepare("SELECT created_at FROM oauth_states WHERE state_hash = ?").get(stateHash);
    db.prepare("DELETE FROM oauth_states WHERE state_hash = ?").run(stateHash);
    if (!stateRow || Date.now() - stateRow.created_at > 10 * 60 * 1000) return res.status(400).send("Invalid or expired OAuth state. Please try connecting again.");
    if (!req.query.code) return res.status(400).send("Meta did not return an authorization code.");
    const redirect_uri = oauthRedirectUri(req);
    const shortToken = await graphTokenRequest({ client_id: META_APP_ID, client_secret: APP_SECRET, redirect_uri, code: String(req.query.code) });
    const longToken = await graphTokenRequest({ grant_type: "fb_exchange_token", client_id: META_APP_ID, client_secret: APP_SECRET, fb_exchange_token: shortToken.access_token });
    const secured = encryptToken(longToken.access_token);
    const expiresAt = longToken.expires_in ? new Date(Date.now() + Number(longToken.expires_in) * 1000).toISOString() : null;
    db.prepare("INSERT INTO meta_tokens (encrypted_token,iv,auth_tag,token_type,expires_at,scopes,created_at) VALUES (?,?,?,?,?,?,?)")
      .run(secured.encrypted, secured.iv, secured.tag, longToken.token_type || "bearer", expiresAt, LOGIN_SCOPES, new Date().toISOString());
    return res.redirect("/?facebook_connected=1");
  } catch (error) {
    console.error("Meta OAuth exchange failed:", error.message);
    return res.status(502).send(`Could not exchange the Meta token: ${String(error.message).replace(/[<>]/g, "")}. Check your App ID, App Secret, redirect URI and permissions, then try again.`);
  }
});

app.get("/api/token/status", dashboardAuth, (req, res) => {
  const row = db.prepare("SELECT token_type,expires_at,scopes,created_at FROM meta_tokens ORDER BY id DESC LIMIT 1").get();
  res.json({ connected: Boolean(row), token_type: row?.token_type || null, expires_at: row?.expires_at || null, scopes: row?.scopes || null, created_at: row?.created_at || null });
});
app.post("/api/token/reveal", dashboardAuth, (req, res) => {
  const row = db.prepare("SELECT * FROM meta_tokens ORDER BY id DESC LIMIT 1").get();
  if (!row) return res.status(404).json({ error: "No Meta token has been connected yet." });
  try { return res.json({ access_token: decryptToken(row), expires_at: row.expires_at }); }
  catch { return res.status(500).json({ error: "Could not decrypt the saved token. Check TOKEN_ENCRYPTION_KEY." }); }
});

// Generic callback endpoint for external services and your own applications.
app.all("/callback", (req, res) => {
  let payload;
  if (Buffer.isBuffer(req.body)) {
    const text = req.body.toString("utf8");
    try { payload = JSON.parse(text); } catch { payload = { raw_text: text }; }
  } else payload = req.body || req.query || {};
  const id = insertEvent({
    source: "callback",
    eventType: req.query.event || req.get("x-event-type") || req.method,
    req, payload, signatureValid: null, status: "received",
    note: "Generic callback captured; configure provider-specific signature verification before relying on it."
  });
  return res.status(200).json({ ok: true, received: true, event_id: id });
});

app.get("/health", (req, res) => res.json({ ok: true, service: "meta-webhook-callback", time: new Date().toISOString() }));
app.get("/api/events", dashboardAuth, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const rows = db.prepare("SELECT * FROM events ORDER BY id DESC LIMIT ?").all(limit);
  res.json(rows.map(r => ({ ...r, headers: JSON.parse(r.headers || "{}"), payload: safeJson(r.payload) })));
});
app.get("/api/stats", dashboardAuth, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) AS n FROM events").get().n;
  const today = db.prepare("SELECT COUNT(*) AS n FROM events WHERE received_at >= ?").get(new Date(new Date().setHours(0,0,0,0)).toISOString()).n;
  const rejected = db.prepare("SELECT COUNT(*) AS n FROM events WHERE status='rejected'").get().n;
  const latest = db.prepare("SELECT received_at FROM events ORDER BY id DESC LIMIT 1").get();
  res.json({ total, today, rejected, latest: latest?.received_at || null });
});
app.delete("/api/events", dashboardAuth, (req, res) => {
  db.prepare("DELETE FROM events").run();
  res.json({ ok: true });
});
function safeJson(s) { try { return JSON.parse(s); } catch { return s; } }

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, "0.0.0.0", () => console.log(`Webhook dashboard listening on ${PORT}`));
